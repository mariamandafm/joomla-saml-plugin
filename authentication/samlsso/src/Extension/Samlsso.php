<?php
declare(strict_types=1);

namespace Joomla\Plugin\Authentication\Samlsso\Extension;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Event\User\AuthenticationEvent;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\Database\DatabaseAwareTrait;
use Joomla\Database\ParameterType;
use Joomla\Event\SubscriberInterface;

\defined("_JEXEC") or die;

/**
 * Authentication plugin — valida token SAML emitido pelo saml-login.php.
 *
 * Responsabilidades:
 *  - Validar assinatura HMAC do token
 *  - Validar expiração
 *  - Validar e consumir nonce (proteção contra replay)
 *  - Verificar se o usuário existe na allowlist (ew8ur_users)
 *  - Retornar STATUS_SUCCESS com username do Joomla
 */
final class Samlsso extends CMSPlugin implements SubscriberInterface
{
    use DatabaseAwareTrait;

    private const SECRET_FILE    = "/var/www/simplesamlphp/config/saml-bridge-secret.php";
    private const NONCE_DIR      = "/var/www/html/joomla/tmp/saml_nonces";
    private const NONCE_WINDOW   = 120; // segundos de validade do nonce

    public static function getSubscribedEvents(): array
    {
        return ["onUserAuthenticate" => "onUserAuthenticate"];
    }

    public function onUserAuthenticate(AuthenticationEvent $event): void
    {
        $credentials = $event->getCredentials();
        $response    = $event->getAuthenticationResponse();

        $token = $credentials["saml_token"] ?? "";
        $sig   = $credentials["saml_sig"]   ?? "";

        // Não é uma tentativa de auth SAML — deixa outros plugins actuarem
        if (empty($token)) {
            return;
        }

        $secret = $this->getSecret();

        // 1. Valida assinatura HMAC-SHA256
        if (empty($secret) || !hash_equals(hash_hmac("sha256", $token, $secret), $sig)) {
            $this->deny($response, "Assinatura SAML inválida.", "assinatura-invalida");
            return;
        }

        // 2. Decodifica e valida expiração
        $data = json_decode(base64_decode($token), true);
        if (!is_array($data) || ($data["exp"] ?? 0) < time()) {
            $this->deny($response, "Token SAML expirado.", "token-expirado");
            return;
        }

        // 3. Valida e consome nonce (single-use — protecção contra replay)
        $nonce     = preg_replace("/[^a-f0-9]/", "", $data["nonce"] ?? "");
        $nonceFile = self::NONCE_DIR . "/nonce_" . $nonce;

        if (empty($nonce) || !file_exists($nonceFile)) {
            $this->deny($response, "Nonce SAML inválido (possível replay).", "nonce-invalido");
            return;
        }

        $nonceAge = time() - (int) file_get_contents($nonceFile);
        @unlink($nonceFile); // Consome o nonce imediatamente

        if ($nonceAge > self::NONCE_WINDOW) {
            $this->deny($response, "Nonce SAML expirado.", "nonce-expirado");
            return;
        }

        $email = trim($data["email"] ?? "");
        $name  = trim($data["name"]  ?? "") ?: $email;

        if (empty($email)) {
            $this->deny($response, "E-mail não recebido do IdP.", "email-vazio");
            return;
        }

        // 4. Verifica allowlist — usuário deve existir e não estar bloqueado
        $db    = $this->getDatabase();
        $query = $db->createQuery()
            ->select([$db->quoteName("id"), $db->quoteName("username"), $db->quoteName("block")])
            ->from($db->quoteName("#__users"))
            ->where($db->quoteName("email") . " = :email")
            ->bind(":email", $email);
        $db->setQuery($query);
        $user = $db->loadObject();

        if (!$user) {
            $this->deny(
                $response,
                "Usuário autenticado via federação, mas não autorizado para acessar este ambiente administrativo.",
                "usuario-nao-cadastrado:" . $email
            );
            return;
        }

        if ((int) $user->block === 1) {
            $this->deny($response, "Conta bloqueada. Contate o administrador.", "conta-bloqueada:" . $email);
            return;
        }

        // 5. Actualiza nome com dados frescos do IdP (opcional mas útil)
        $userId = (int) $user->id;
        $db->setQuery(
            $db->createQuery()
                ->update($db->quoteName("#__users"))
                ->set($db->quoteName("name") . " = :name")
                ->where($db->quoteName("id") . " = :id")
                ->bind(":name", $name)
                ->bind(":id", $userId, ParameterType::INTEGER)
        );
        $db->execute();

        // 6. Sucesso — retorna username Joomla para o plg_user_joomla criar a sessão
        $response->status        = Authentication::STATUS_SUCCESS;
        $response->type          = "SAMLSSO";
        $response->username      = $user->username;
        $response->email         = $email;
        $response->fullname      = $name;
        $response->error_message = "";

        $this->logAudit(Log::INFO, "Login SSO autorizado: " . $email . " -> " . $user->username);
    }

    private function deny(object $response, string $msg, string $reason): void
    {
        $response->status        = Authentication::STATUS_FAILURE;
        $response->error_message = $msg;
        $this->logAudit(Log::WARNING, "Login SSO negado [" . $reason . "]: " . $msg);
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
        Log::add("[SAML SSO Auth] " . $message, $level, "samlsso");
    }
}
