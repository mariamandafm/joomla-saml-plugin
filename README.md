# SAML SSO para Joomla 6

Autenticação federada via SAML 2.0 para o painel administrativo do Joomla (`/administrator`).  
O frontend do site permanece inalterado. O login local por usuário/senha continua funcionando normalmente.

---

## Visão geral da arquitetura

```
Usuário clica "Login com Federação"
        │
        ▼
[saml-login.php]  ──────────────────────────────────────────────
        │  Redireciona para o IdP via SimpleSAMLphp SP           │
        ▼                                                         │
[IdP SAML 2.0]                                                    │
        │  Autentica o usuário e retorna asserção SAML            │
        ▼                                                         │
[saml-login.php]  ◄─────────────────────────────────────────────
        │  Extrai email + nome dos atributos SAML
        │  Cria nonce de uso único (anti-replay)
        │  Assina payload com HMAC-SHA256
        │  Redireciona para /administrator?saml_token=...&saml_sig=...
        ▼
[plg_system_samlsso — onAfterInitialise]
        │  Valida assinatura HMAC (verificação rápida)
        │  Verifica expiração do token (60 segundos)
        │  Chama $app->login(credentials)
        ▼
[plg_authentication_samlsso — onUserAuthenticate]
        │  Valida HMAC completo
        │  Valida expiração
        │  Consome nonce (uso único — proteção anti-replay)
        │  Consulta #__users por email (allowlist)
        │  Verifica se a conta não está bloqueada
        │  Retorna STATUS_SUCCESS com username Joomla
        ▼
[plg_user_joomla — onUserLogin]  (nativo do Joomla)
        │  Cria sessão de backend (client_id = 1)
        ▼
Painel administrativo do Joomla (/administrator/)
```
---

## Pré-requisitos

| Requisito | Versão mínima | Notas |
|-----------|---------------|-------|
| Joomla | 6.x | Testado na 6.1.0. Compatível com Joomla 5 com ajustes menores (ver nota ao final) |
| PHP | 8.1+ | `json`, `openssl`, `mbstring` habilitados |
| SimpleSAMLphp | 2.x | SP configurado com `authsource` `default-sp` |
| Servidor web | Apache / Nginx | Apache com `mod_rewrite`; Nginx com equivalente |

O SimpleSAMLphp deve estar instalado e com o Service Provider (SP) configurado para comunicar com o IdP da federação antes de prosseguir.

---

## Componentes
| Componente | Função|
|-|-|
|`saml-login.php`|Ponto de entrada do fluxo federado. É um script PHP independente do Joomla (não carrega o bootstrap do CMS) que age como intermediário entre o Joomla e o SimpleSAMLphp.|
|`plg_system_samlsso`|Plugin do tipo system que intercepta o evento `onAfterInitialise` no contexto do administrador. É a porta de entrada do callback SAML dentro do Joomla.|
|`plg_authentication_samlsso`|Plugin do tipo `authentication` que implementa a validação completa do token SAML e a consulta à allowlist.|

---

## Allowlist de usuários

O acesso federado é restrito a usuários **já cadastrados** no Joomla com o mesmo e-mail que o IdP envia.

Para **autorizar um novo usuário** via federação:

1. Acesse **Usuários → Gerenciar** no painel admin do Joomla
2. Crie ou edite o usuário
3. Certifique-se de que o campo **E-mail** corresponde exatamente ao que o IdP retorna
4. Atribua os grupos de acesso desejados
5. Certifique-se de que a conta **não está bloqueada**

Para **revogar o acesso federado** de um usuário sem excluir a conta, basta **bloquear a conta** no Joomla (o plugin verifica o campo `block`).