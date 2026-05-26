<?php
declare(strict_types=1);
/**
 * SAML Login Bridge — executa FORA do bootstrap do Joomla.
 * Autentica via SimpleSAMLphp SP e redireciona para o admin do Joomla com token assinado.
 */

define("SAML_NONCE_DIR", "/var/www/html/joomla/tmp/saml_nonces");
define("SAML_SECRET_FILE", "/var/www/simplesamlphp/config/saml-bridge-secret.php");

if (!file_exists(SAML_SECRET_FILE)) {
    error_log("[SAML Bridge] Arquivo de secret não encontrado.");
    header("Location: /administrator/index.php?saml_error=config");
    exit;
}
require SAML_SECRET_FILE;

if (!defined("SAML_BRIDGE_SECRET") || empty(SAML_BRIDGE_SECRET)) {
    error_log("[SAML Bridge] SAML_BRIDGE_SECRET não definido.");
    header("Location: /administrator/index.php?saml_error=config");
    exit;
}

require_once "/var/www/simplesamlphp/vendor/autoload.php";

$as = new \SimpleSAML\Auth\Simple("default-sp");

if (!$as->isAuthenticated()) {
    $as->login([
        "ReturnTo" => "https://test.gidlab.local/saml-login.php",
        "KeepPost" => false,
    ]);
    exit;
}

$attrs = $as->getAttributes();

// Extrai email (múltiplos atributos possíveis conforme federação)
$email = $attrs["urn:oid:0.9.2342.19200300.100.1.3"][0]  // mail
      ?? $attrs["mail"][0]
      ?? $attrs["email"][0]
      ?? $attrs["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"][0]   // eduPersonPrincipalName
      ?? "";

if (empty($email)) {
    error_log("[SAML Bridge] Nenhum atributo de email recebido. Attrs: " . implode(", ", array_keys($attrs)));
    header("Location: /administrator/index.php?saml_error=no_email");
    exit;
}

// Extrai nome de exibição
$name = $attrs["urn:oid:2.16.840.1.113730.3.1.241"][0]  // displayName
     ?? $attrs["displayName"][0]
     ?? $attrs["urn:oid:2.5.4.3"][0]                     // cn
     ?? $attrs["cn"][0]
     ?? "";

// Nonce para protecção contra replay attacks
$nonce     = bin2hex(random_bytes(16));
$nonceFile = SAML_NONCE_DIR . "/nonce_" . $nonce;

if (!is_dir(SAML_NONCE_DIR)) {
    mkdir(SAML_NONCE_DIR, 0750, true);
}

file_put_contents($nonceFile, (string) time(), LOCK_EX);
chmod($nonceFile, 0600);

$payload = base64_encode(json_encode([
    "email" => $email,
    "name"  => $name,
    "nonce" => $nonce,
    "exp"   => time() + 60,
], JSON_THROW_ON_ERROR));

$sig = hash_hmac("sha256", $payload, SAML_BRIDGE_SECRET);

error_log("[SAML Bridge] Autenticado: " . $email . " -> redirect para admin");

header("Location: https://test.gidlab.local/administrator/index.php"
    . "?saml_token=" . rawurlencode($payload)
    . "&saml_sig="   . $sig);
exit;
