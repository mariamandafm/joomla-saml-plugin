<?php
declare(strict_types=1);

namespace Joomla\Plugin\System\Samlsso\Extension;

use Joomla\CMS\Application\AdministratorApplication;
use Joomla\CMS\Event\Application\AfterInitialiseEvent;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Event\SubscriberInterface;

\defined("_JEXEC") or die;

/**
 * System plugin — processa o callback SAML quando o utilizador inicia o fluxo
 * clicando em "Login com Federação" na página de login do admin.
 *
 * Fluxo:
 *  1. Utilizador clica "Login com Federação" → saml-login.php → SimpleSAMLphp
 *  2. SimpleSAMLphp autentica → redireciona com saml_token + saml_sig
 *  3. Este plugin valida o token e chama $app->login()
 *  4. O plugin de autenticação (plg_authentication_samlsso) valida e libera o acesso
 */
final class Samlsso extends CMSPlugin implements SubscriberInterface
{
    private const SAML_LOGIN_URL  = "https://test.gidlab.local/saml-login.php";
    private const SECRET_FILE     = "/var/www/simplesamlphp/config/saml-bridge-secret.php";
    private const LOG_CATEGORY    = "samlsso";
    private const NONCE_DIR       = "/var/www/html/joomla/tmp/saml_nonces";
    private const NONCE_MAX_AGE   = 300;

    public static function getSubscribedEvents(): array
    {
        return ["onAfterInitialise" => "onAfterInitialise"];
    }

    public function onAfterInitialise(AfterInitialiseEvent $event): void
    {
        $app = $event->getApplication();

        // Actua apenas no contexto admin
        if (!($app instanceof AdministratorApplication)) {
            return;
        }

        // Configura logger dedicado para auditoria SSO
        $this->setupAuditLogger();

        $input = $app->getInput();
        $token = $input->getString("saml_token", "");
        $sig   = $input->getString("saml_sig", "");

        // Callback do IdP com token SAML — processar login federado
        if (!empty($token) && !empty($sig)) {
            $this->processSamlCallback($app, $token, $sig);
        }
    }

    private function processSamlCallback(AdministratorApplication $app, string $token, string $sig): void
    {
        $secret = $this->getSecret();

        if (empty($secret)) {
            $this->logAudit(Log::ERROR, "Secret SAML não configurado");
            $app->enqueueMessage("Erro de configuração SSO. Contacte o administrador.", "error");
            $app->redirect("/administrator/index.php?saml_error=1");
            return;
        }

        // Pré-validação rápida da assinatura (validação completa ocorre no auth plugin)
        $expectedSig = hash_hmac("sha256", $token, $secret);
        if (!hash_equals($expectedSig, $sig)) {
            $this->logAudit(Log::WARNING, "Assinatura SAML inválida no callback");
            $app->enqueueMessage("Token SSO inválido.", "error");
            $app->redirect("/administrator/index.php?saml_error=1");
            return;
        }

        $data = json_decode(base64_decode($token), true);
        if (!is_array($data) || ($data["exp"] ?? 0) < time()) {
            $this->logAudit(Log::WARNING, "Token SAML expirado");
            $app->enqueueMessage("Sessão SSO expirada. Por favor, tente novamente.", "warning");
            $app->redirect(self::SAML_LOGIN_URL);
            return;
        }

        $email = $data["email"] ?? "unknown";
        $this->logAudit(Log::INFO, "Tentativa de login SSO para: " . $email);

        // Limpar nonces antigos (manutenção proactiva)
        $this->cleanupOldNonces();

        // Delegar autenticação ao AdministratorApplication::login() + auth plugin
        $result = $app->login(
            ["saml_token" => $token, "saml_sig" => $sig],
            ["silent" => true]
        );

        if ($result === true) {
            $identity = $app->getIdentity();
            $username = $identity ? $identity->username : "unknown";
            $this->logAudit(Log::INFO, "LOGIN SSO BEM-SUCEDIDO: " . $email . " -> usuario Joomla: " . $username);
            $app->redirect("/administrator/");
        } else {
            $this->logAudit(Log::WARNING, "LOGIN SSO NEGADO: " . $email);
            $app->enqueueMessage(
                "Usuário autenticado via federação, mas não autorizado para acessar este ambiente administrativo.",
                "error"
            );
            $app->redirect("/administrator/index.php?saml_error=1");
        }
    }

    private function setupAuditLogger(): void
    {
        static $loggerAdded = false;
        if ($loggerAdded) {
            return;
        }
        $loggerAdded = true;

        Log::addLogger(
            ["text_file" => "samlsso_audit.php"],
            Log::ALL,
            [self::LOG_CATEGORY]
        );
    }

    private function cleanupOldNonces(): void
    {
        if (!is_dir(self::NONCE_DIR)) {
            return;
        }

        $now = time();
        foreach (glob(self::NONCE_DIR . "/nonce_*") as $file) {
            if (is_file($file) && ($now - (int) @file_get_contents($file)) > self::NONCE_MAX_AGE) {
                @unlink($file);
            }
        }
    }

    private function getSecret(): string
    {
        if (file_exists(self::SECRET_FILE) && !defined("SAML_BRIDGE_SECRET")) {
            require_once self::SECRET_FILE;
        }
        return defined("SAML_BRIDGE_SECRET") ? SAML_BRIDGE_SECRET : "";
    }

    private function logAudit(int $level, string $message): void
    {
        Log::add("[SAML SSO] " . $message, $level, self::LOG_CATEGORY);
    }
}
