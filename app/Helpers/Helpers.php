<?php

namespace App\Helpers;

class Helpers
{


    // ================================= //
    // FUNCTION GENERATE SLUG
    // ================================= //
    public function generateSlug()
    {
        $characters = 'abcdefghijklmnopqrstuvwxyz';
        $shuffled   = str_shuffle($characters);
        $slug       = substr($shuffled, 0, -25);
        $slug      .= bin2hex(random_bytes(5)) . "-e" . date('dthis');

        return $slug;
    }


    // ================================= //
    // FUNCTION GENERATE RANDOM STRING
    // ================================= //
    function generateRandomString($panjang)
    {
        $karakter        = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $panjangKarakter = strlen($karakter);
        $randomString    = '';

        for ($i = 0; $i < $panjang; $i++) {
            $randomString .= $karakter[rand(0, $panjangKarakter - 1)];
        }

        return $randomString;
    }


    // =================================== //
    // GENERATE CRUL
    // =================================== //
    function makeCurlRequest($url, $method = 'GET', $headers = [], $body = null)
    {
        $ch = curl_init($url);

        // SET cURL OPTIONS
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
        ];

        if (!empty($headers)) {
            $options[CURLOPT_HTTPHEADER] = $headers;
        }

        if ($method === 'POST' && !is_null($body)) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }

        curl_setopt_array($ch, $options);

        return $response = curl_exec($ch);

        if (curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch);
        }

        curl_close($ch);

        return $response;
    }

    // =================================== //
    // GENERATE CRUL FOR TESTING
    // =================================== //
    function makeCurlRequestz($url, $method = 'GET', $headers = [], $body = null)
    {
        $ch = curl_init($url);

        // SET cURL OPTIONS
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
        ];

        if (!empty($headers)) {
            $options[CURLOPT_HTTPHEADER] = $headers;
        }

        if ($method === 'POST' && !is_null($body)) {
            $options[CURLOPT_POSTFIELDS] = $body;
        }

        curl_setopt_array($ch, $options);

        // Build the cURL command for debugging
        $curlCommand = "curl --location '$url' \\\n";
        foreach ($headers as $header) {
            $curlCommand .= "--header '$header' \\\n";
        }
        if (
            $method === 'POST' && !is_null($body)
        ) {
            $jsonBody = json_encode(json_decode($body), JSON_PRETTY_PRINT);
            $curlCommand .= "--data '$jsonBody' \\\n";
        }
        $curlCommand .= "--request $method";

        $datas =  "Generated cURL command for debug:\n$curlCommand\n";

        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            echo 'cURL error: ' . curl_error($ch);
        }

        curl_close($ch);

        return [
            "response" => $response,
            "data"     => $datas
        ];
    }

    // =================================== //
    // GENERATE UNIQUE NUMERIC
    // =================================== //
    function generateUniqueNumeric()
    {
        $numeric  = rand(100000000000000000, 999999999999999999);
        $numeric1 = rand(100000000000000000, 999999999999999999);

        $result =  $numeric . $numeric1;
        return "$result";
    }


    // =================================== //
    // CHECK MERCHANT
    // =================================== //
    public function checkMerchant()
    {
        // UNTUK MERCHANT E-KARCIS
        $privateKey    = env('EKARCIS_RSA_PRIVATE_KEY');
        $clientId      = env('EKARCIS_CLIENT_ID');
        $mid           = env('EKARCIS_MID');
        $clientSeccret = env('EKARCIS_CLIENT_SECRET');

        return [
            'private_key'   => $privateKey,
            'client_id'     => $clientId,
            'mid'           => $mid,
            'client_secret' => $clientSeccret
        ];
    }


    // =================================== //
    // CREATE RSA (Rivest Shamir Adleman)
    // =================================== //
    public function createRSA($xTimestamp = null)
    {
        // UNTUK MERCHANT E-KARCIS
        $privatekey = env('EKARCIS_RSA_PRIVATE_KEY');
        $clientId   = env('EKARCIS_CLIENT_ID');

        $privateKeyId = openssl_pkey_get_private($privatekey);

        // GENERATE TIMESTAMP FOR X-TIMESTAMP HEADER or USE NEW TIMESTAMP
        $timestamp = $xTimestamp == null ? self::generateTimestamp() : $xTimestamp;

        openssl_sign($clientId . "|" . $timestamp, $signature, $privateKeyId, 'RSA-SHA256');

        $base64Str = base64_encode($signature);

        return [
            'x-signature' => $base64Str,
            'x-timestamp' => $timestamp
        ];
    }

    // ================================= //
    // CREATE SIGNATURE SERVICE
    // ================================= //
    public function createSignatureService($httpMethod, $endpointUrl, $accessToken, $requestBody, $timestamp, $clientSecret)
    {
        $minifyBody           = self::minifyBody($requestBody);
        $hexEncodedMinifyBody = hash('sha256', $minifyBody);
        $stringToSignature    = implode(':', [$httpMethod, $endpointUrl, $accessToken, $hexEncodedMinifyBody, $timestamp]);

        return self::generateSignature($clientSecret, $stringToSignature);
    }

    // ================================ //
    // GENERATE ACCESS TOKEN B2B BY EC
    // ================================ //
    public function generateAccessToken()
    {
        // CREATE RSA
        $result = self::createRSA();
        if (!$result) {
            return ResponseFormatter::error("EC Not Found", 404, 404);
        }

        // CHECK MERCHENT SOCCER ACADEMIA / E-KARCIS
        $checkMerchant = self::checkMerchant();
        if (empty($checkMerchant)) {
            return ResponseFormatter::error("EC Not Found", 404, 404);
        }

        // RETRIVE DATA FOR CHECK MARCHENT
        $xClientKey = $checkMerchant['client_id'];

        // GENERATE PAYLOAD FOR ACCESS TOKEN B2B
        $xSignature = $result['x-signature'];
        $xTimestamp = $result['x-timestamp'];
        $url        = env('SANDBOX') . "/snap-service/snap/v1.0/access-token/b2b";
        $headers    = array(
            'Content-Type: application/json',
            'x-client-key:' . $xClientKey,
            'x-timestamp:' . $xTimestamp,
            'x-signature:' . $xSignature
        );

        $body = array(
            "grantType" => "client_credentials",
        );
        $body = json_encode($body);

        // SEND API ACCESS TOKEN B2B TO ASTRAPAY
        $responseToken = json_decode(self::makeCurlRequest($url, "POST", $headers, $body), true);
        if ($responseToken['responseCode'] !== "2007300") {
            return $responseToken;
        }

        return [
            "response"      => $responseToken,
            "timestamp"     => $xTimestamp,
            "client_id"     => $xClientKey,
            "access_token"  => $responseToken['accessToken'],
            "merchant_id"   => $checkMerchant['mid'],
            "client_secret" => $checkMerchant['client_secret']
        ];
    }

    // ======================================== //
    // GENERATE ACCESS TOKEN B2B FOR ASTRA PAY
    // ======================================= //
    public function generateAccessTokenforAstrapay($xTimestamp)
    {
        // CREATE RSA
        $result = self::createRSA($xTimestamp);
        if (!$result) {
            return ResponseFormatter::error("EC Not Found", 404, 404);
        }

        // CHECK MERCHENT SOCCER ACADEMIA / E-KARCIS
        $checkMerchant = self::checkMerchant();
        if (empty($checkMerchant)) {
            return ResponseFormatter::error("EC Not Found", 404, 404);
        }

        // RETRIVE DATA FOR CHECK MARCHENT
        $xClientKey = $checkMerchant['client_id'];

        // GENERATE PAYLOAD FOR ACCESS TOKEN B2B
        $xSignature = $result['x-signature'];
        $xTimestamp = $result['x-timestamp'];
        $url        = env('SANDBOX') . "/snap-service/snap/v1.0/access-token/b2b";
        $headers    = array(
            'Content-Type: application/json',
            'x-client-key:' . $xClientKey,
            'x-timestamp:' . $xTimestamp,
            'x-signature:' . $xSignature
        );

        $body = array(
            "grantType" => "client_credentials",
        );
        $body = json_encode($body);

        // SEND API ACCESS TOKEN B2B TO ASTRAPAY
        $responseToken = json_decode(self::makeCurlRequest($url, "POST", $headers, $body), true);
        if ($responseToken['responseCode'] !== "2007300") {
            return $responseToken;
        }

        return [
            "response"     => $responseToken,
            "access_token" => $responseToken['accessToken'],
        ];
    }

    // ================================ //
    // CHECK STATUS PAYMENT H2H
    // ================================ //
    public function checkStatusPayment($harga, $trxReferenceNo)
    {
        // GENERATE ACCESS TOKEN
        $resultB2B = self::generateAccessToken("6899b9309d62ddf1a4f381e1f2b93957");
        if (!isset($resultB2B['access_token'])) {
            return $resultB2B;
        }

        // GENERATE PAYLOAD SIGNATUR SERVICE
        $endpointUrl = "/merchant-service/snap/v1.0/debit/status";

        $requestBody = [
            "originalPartnerReferenceNo" => $trxReferenceNo, // ID transaksi dari Merchant/Partner (Merchant/Partner Transaction ID)
            "originalReferenceNo"        => "",              // ID transaksi dari AstraPay
            "serviceCode"                => "54",
            "amount"                     => [
                "value"                  => $harga,
                "currency"               => "IDR"
            ]
        ];
        $requestBodyJson = json_encode($requestBody);

        // CREATE SIGNATURE SERVICE
        $signatureService = self::createSignatureService("POST", $endpointUrl, $resultB2B['access_token'], $requestBodyJson, $resultB2B['timestamp'], $resultB2B['client_secret']);

        // PAYLOAD FOR HIT API STATUS PAYMENT HOST TO HOST
        $externalId = (string)self::generateUniqueNumeric();
        $url        = env('SANDBOX') . $endpointUrl;

        $headers = [
            'Authorization: Bearer ' . $resultB2B['access_token'],
            'Content-Type: application/json',
            'x-timestamp: ' . $resultB2B['timestamp'],
            'x-signature: ' . $signatureService,
            'x-partner-id: ' . $resultB2B['client_id'],
            'x-external-id: ' . $externalId,
            'channel-id: ' . "00155"
        ];

        $body = [
            "originalPartnerReferenceNo" => $trxReferenceNo,
            "originalReferenceNo"        => "",
            "serviceCode"                => "54",
            "amount"                     => [
                "value"                  => $harga,
                "currency"               => "IDR"
            ],
        ];
        $body = json_encode($body);

        // SEND API STATUS PAYMENT H2H
        return json_decode(self::makeCurlRequest($url, "POST", $headers, $body), true);
    }

    // ================================ //
    public function statusPaymentH2H($harga, $trxReferenceNo, $astrapayTrxId)
    {
        $originalReferenceNo = $astrapayTrxId == null ? "" : $astrapayTrxId;

        // GENERATE ACCESS TOKEN
        $resultB2B = self::generateAccessToken();
        if (!isset($resultB2B['access_token'])) {
            return $resultB2B;
        }

        // GENERATE PAYLOAD SIGNATUR SERVICE
        $endpointUrl = "/merchant-service/snap/v1.0/debit/status";

        $requestBody = [
            "originalPartnerReferenceNo" => $trxReferenceNo,      // ID transaksi dari Merchant/Partner (Merchant/Partner Transaction ID)
            "originalReferenceNo"        => $originalReferenceNo, // ID transaksi dari AstraPay
            "serviceCode"                => "54",
            "amount"                     => [
                "value"                  => $harga,
                "currency"               => "IDR"
            ]
        ];
        $requestBodyJson = json_encode($requestBody);

        // CREATE SIGNATURE SERVICE
        $signatureService = self::createSignatureService("POST", $endpointUrl, $resultB2B['access_token'], $requestBodyJson, $resultB2B['timestamp'], $resultB2B['client_secret']);

        // PAYLOAD FOR HIT API STATUS PAYMENT HOST TO HOST
        $externalId = (string)self::generateUniqueNumeric();
        $url        = env('SANDBOX') . $endpointUrl;

        $headers = [
            'Authorization: Bearer ' . $resultB2B['access_token'],
            'Content-Type: application/json',
            'x-timestamp: ' . $resultB2B['timestamp'],
            'x-signature: ' . $signatureService,
            'x-partner-id: ' . $resultB2B['client_id'],
            'x-external-id: ' . $externalId,
            'channel-id: ' . "00155"
        ];

        $body = [
            "originalPartnerReferenceNo" => $trxReferenceNo,
            "originalReferenceNo"        => $originalReferenceNo,
            "serviceCode"                => "54",
            "amount"                     => [
                "value"                  => $harga,
                "currency"               => "IDR"
            ],
        ];
        $body = json_encode($body);

        // SEND API STATUS PAYMENT H2H
        return json_decode(self::makeCurlRequest($url, "POST", $headers, $body), true);
    }


    // ================================================= //
    //            PRIVATE FUNCTION START                 
    // ================================================= //

    // ==================================== //
    // PRIVATE FUNCTION GENERATE TIMESTAMP
    // ==================================== //
    private static function generateTimestamp()
    {
        // Set zona waktu menjadi Asia/Jakarta
        date_default_timezone_set('Asia/Jakarta');

        // Mendapatkan waktu saat ini dalam format yang diinginkan
        return date('Y-m-d\TH:i:sP');
    }


    // ================================= //
    // PRIVATE FUNCTION MINIFY BODY
    // ================================= //
    private static function minifyBody($input)
    {
        $jsonObject = json_decode($input);
        return json_encode($jsonObject);
    }


    // =================================== //
    // PRIVATE FUNCTION GENERATE SIGNATURE
    // =================================== //
    private static function generateSignature($secret, $input)
    {
        $hash = hash_hmac('sha512', $input, $secret, true);
        return base64_encode($hash);
    }
}
