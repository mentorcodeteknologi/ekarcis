<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Helpers\ResponseFormatter;
use Illuminate\Support\Facades\Validator;
use Exception;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Storage;

class AstrapayController extends Controller
{

    // ================================ //
    // FUNCTION BILLING UPDATE STATUS   //
    // ================================ //
    public function billingUpdateStatus()
    {
        try {
            $trxId = request('merchantTransactionId');
            if ($trxId == null) {
                return redirect()->to(route('turnamen.indexFront'))->with('error', 'Pembayaran gagal');
            }

            // HIT API STATUS PAYMENT H2H
            // $response =  $this->helper->statusPaymentH2H(null, $transaction->harga, $trxId, $transaction->astrapay_trx_id);
            // if ($response['responseCode'] != '2005500' || $response['responseMessage'] != 'Successful') {
            //     return redirect()->to(route('turnamen.indexFront'))->with('error', 'Pembayaran gagal');
            // }

            return "success";
            // return redirect()->to(route('turnamen.going_front', ['id' => $transaction->turnamen_id]))->with('success', 'Pembayaran berhasil');
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }

    // ============================ //
    // API CREATE ACCESS TOKEN B2B
    // ============================ //
    public function createAccessTokenB2B(Request $request)
    {
        try {
            // $ec = $request->input('ec') ?? "6899b9309d62ddf1a4f381e1f2b93957";
            // $ec = $request->input('ec');
            // if (empty($ec)) {
            //     return ResponseFormatter::error("Param Not Found", 404);
            // }

            // GENERATE ACCESS TOKEN
            return $resultB2B = $this->helper->generateAccessToken();
            if (!isset($resultB2B['access_token'])) {
                return $resultB2B;
            }

            return $resultB2B['response'];
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }


    // ============================ //
    // API CREATE PAYMENT H2H
    // ============================ //
    public function createPaymentH2H(Request $request)
    {
        try {
            // VALIDATION REQUIRED INPUT
            $request->validate([
                // 'user_id'     => ['required', 'uuid'],
                // 'tim_id'      => ['required', 'uuid'],
                'harga'       => ['required', 'string', 'max:255'],
                'description' => ['required', 'string', 'max:255']
            ]);

            // $ec          = $request->input('ec');
            $harga       = $request->input('harga');
            $description = $request->input('description');
            $userId      = $request->input('user_id');
            $turnamenId  = $request->input('turnamen_id') ?? null;
            $timId       = $request->input('tim_id') ?? null;

            // if (empty($ec)) {
            //     return ResponseFormatter::error("Param Not Found", 404);
            // }

            // GENERATE ACCESS TOKEN
            $resultB2B = $this->helper->generateAccessToken();
            if (!isset($resultB2B['access_token'])) {
                return $resultB2B;
            }

            // RETRIVE DATA FOR GENERATE ACCESS TOKEN
            $xClientKey   = $resultB2B['client_id'];
            $merchantId   = $resultB2B['merchant_id'];
            $clientSecret = $resultB2B['client_secret'];
            $accessToken  = $resultB2B['access_token'];
            $xTimestamp   = $resultB2B['timestamp'];

            // GENERATE PAYLOAD SIGNATUR SERVICE
            $endpointUrl    = "/merchant-service/snap/v1.0/debit/payment-host-to-host";
            $trxReferenceNo = "TRX" . date("Ymd") . mt_rand(100000, 999999);

            $requestBody = [
                "partnerReferenceNo" => $trxReferenceNo,
                "merchantId"         => $merchantId,
                "amount"             => [
                    "value"          => $harga,
                    "currency"       => "IDR"
                ],
                "additionalInfo"     => [
                    "description"    => $description
                ]
            ];
            $requestBodyJson = json_encode($requestBody);

            // CREATE SIGNATURE SERVICE
            $signatureService = $this->helper->createSignatureService("POST", $endpointUrl, $accessToken, $requestBodyJson, $xTimestamp, $clientSecret);

            // PAYLOAD FOR HIT API PAYMENT HOST TO HOST
            $externalId = (string)$this->helper->generateUniqueNumeric();
            $url        = env('SANDBOX') . $endpointUrl;

            $headers = [
                'Authorization: Bearer ' . $accessToken,
                'Content-Type: application/json',
                'x-timestamp: ' . $xTimestamp,
                'x-signature: ' . $signatureService,
                'x-partner-id: ' . $xClientKey,
                'x-external-id: ' . $externalId,
                'channel-id: ' . "00854"
            ];

            $body = [
                "partnerReferenceNo" => $trxReferenceNo,
                "merchantId"         => $merchantId,
                "amount"             => [
                    "value"          => $harga,
                    "currency"       => "IDR"
                ],
                "additionalInfo"     => [
                    "description"    => $description
                ]
            ];
            $body = json_encode($body);

            // SEND API PAYMENT H2H
            $responseH2H = json_decode($this->helper->makeCurlRequest($url, "POST", $headers, $body), true);
            if ($responseH2H['responseCode'] != "2005400") {
                return $responseH2H;
            }

            $data = [
                "partner_reference_no" => $trxReferenceNo,
                "mid"                  => $merchantId,
                "client_id"            => $xClientKey,
                "x_timestamp"          => $xTimestamp,
                "harga"                => $harga,
                "external_id"          => (int)$externalId,
                "user_id"              => $userId,
                "turnamen_id"          => $turnamenId,
                "tim_id"               => $timId,
            ];

            return $responseH2H;
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }


    // ============================ //
    // API STATUS PAYMENT
    // ============================ //
    public function statusPaymentH2H(Request $request)
    {
        try {
            // VALIDATION REQUIRED INPUT
            $request->validate([
                'trx_id' => ['required'],
                'harga'  => ['required', 'max:255'],
            ]);

            // $ec             = $request->input('ec') ?? "6899b9309d62ddf1a4f381e1f2b93957";
            $harga          = $request->input('harga');
            $trxReferenceNo = $request->input('trx_id');

            // GENERATE ACCESS TOKEN
            $resultB2B = $this->helper->generateAccessToken();
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
            $signatureService = $this->helper->createSignatureService("POST", $endpointUrl, $resultB2B['access_token'], $requestBodyJson, $resultB2B['timestamp'], $resultB2B['client_secret']);

            // PAYLOAD FOR HIT API STATUS PAYMENT HOST TO HOST
            $externalId = (string)$this->helper->generateUniqueNumeric();
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
            return json_decode($this->helper->makeCurlRequest($url, "POST", $headers, $body), true);

            // FOR TESTING CURL
            // $responseH2H = $this->helper->makeCurlRequestz($url, "POST", $headers, $body);
            // $responseH2H1 = json_decode($responseH2H['response'], true);
            // $responseH2H2 = $responseH2H['data'];

            // return [
            //     $responseH2H1,
            //     $responseH2H2
            // ];
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }


    // ======================================= MY API FOR ASTRAPAY START ======================================= //


    // ========================== //
    // FUNCTION FOR ACCESS TOKEN  //
    // ========================== //
    public function accessToken(Request $request)
    {
        try {
            // REQUEST HEADER
            $headers   = $request->header();
            $validator = Validator::make($headers, [
                'x-client-key' => ['required', 'max:255'],
                'x-timestamp'  => ['required'],
                'x-signature'  => ['required'],
            ]);

            if ($validator->fails()) {
                return ResponseFormatter::error($validator->errors()->first());
            }

            $xSignature = $request->header('x-signature');
            $xTimestamp = $request->header('x-timestamp');

            // $ec = $request->input('ec') ?? "6899b9309d62ddf1a4f381e1f2b93957";
            // GENERATE ACCESS TOKEN
            $resultB2B = $this->helper->generateAccessTokenforAstrapay($xTimestamp);
            if (!isset($resultB2B['access_token'])) {
                return $resultB2B;
            }

            return $resultB2B['response'];

            // $xSignature = $request->header('x-signature');
            // $xTimestamp = $request->header('x-timestamp');
            // $xClientKey = $request->header('x-client-key');

            // // VALIDATION CLIENT ID
            // if ($xClientKey != env('SC_CLIENT_ID')) {
            //     return ResponseFormatter::error("Client ID Not Found", 404);
            // }

            // $currentTime = time();
            // $expiryTime  = $currentTime + 3600; // 1 hour

            // // Payload JWT
            // $payload = array(
            //     "exp"            => $expiryTime,  // Waktu kadaluarsa token
            //     "iat"            => $currentTime, // Waktu token diterbitkan
            //     "jti"            => uniqid(),     // ID token unik
            //     "iss"            => "https://socceracademia.com/",
            //     "aud"            => "account",
            //     "sub"            => "689e2561-9941-438f-82c0-56fc5d4afe0c",
            //     "typ"            => "Bearer",
            //     "acr"            => "1",
            //     "admin"          => true,
            //     "scope"          => "billing",
            //     "client_id"      => rtrim(base64_encode(env('SC_CLIENT_ID')), "="),
            //     "preferred_user" => rtrim(base64_encode(env('SC_CLIENT_SECRET')), "="),
            //     "xTimestamp"     => $xTimestamp,
            // );

            // // Encode token JWT
            // $jwt = JWT::encode($payload, env('JWT_SECRET_KEY'), 'HS256');

            // return ResponseFormatter::success([
            //     "accessToken" => $jwt,
            //     "tokenType"   => "Bearer",
            //     "expiresIn"   => "3600",
            //     "xTimestamp"  => $xTimestamp,
            // ]);
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }


    // ========================== //
    // FUNCTION FOR NOTIFY        //
    // ========================== //
    public function notify(Request $request)
    {
        try {
            // REQUEST HEADER
            $headers   = $request->header();
            $validator = Validator::make($headers, [
                'authorization' => ['required'],
                'x-timestamp'   => ['required'],
                'x-signature'   => ['required'],
                'x-partner-id'  => ['required'],
                'x-external-id' => ['required', 'max:36'],
                'channel-id'    => ['required']
            ]);

            if ($validator->fails()) {
                return ResponseFormatter::errorV1("Bad Request", 400, 56, 00);
            }

            // RETRIVE DATA FOR PAYLOAD HEADER
            $token            = $headers['authorization'][0];
            $token            = substr($token, 7); // Remove Bearer
            $timestamp        = $headers['x-timestamp'][0];
            $xPartnerId       = $headers['x-partner-id'][0];
            $xExternalId      = $headers['x-external-id'][0];
            $signatureService = $headers['x-signature'][0];
            $channelId        = $headers['channel-id'][0];

            // RETRIVE DATA FOR PAYLOAD BODY
            $bodyRaw                    = $request->all();
            $originalPartnerReferenceNo = $bodyRaw['originalPartnerReferenceNo'] ?? "";
            $originalReferenceNo        = $bodyRaw['originalReferenceNo']; // AstraPay Transaction ID
            $merchantId                 = $bodyRaw['merchantId'];
            $latestTransactionStatus    = $bodyRaw['latestTransactionStatus'];
            $finishedTime               = $bodyRaw['finishedTime'];
            $harga                      = $bodyRaw['amount']['value'];
            $currency                   = $bodyRaw['amount']['currency'];

            // VALIDATION MARCHANT ID
            // if ($merchantId != env('SOCCER_MID') && $merchantId != env('SC_MID')) {
            //     return ResponseFormatter::error("Merchant ID Not Found", 404);
            // }

            // VALIDATION TRANSACTION STATUS
            $validationTrx = $this->helper->checkStatusPayment($harga, $originalPartnerReferenceNo);
            if ($validationTrx['responseCode'] != 2005500) {
                $validationTrx['responseCode'] = 4045601;
                return $validationTrx;
            }

            return ResponseFormatter::success([
                "responseCode"    => 2005600,
                "responseMessage" => "Request has been processed successfully"
            ]);
        } catch (Exception $e) {
            return ResponseFormatter::error($e->getMessage());
        }
    }


    // ======================================== MY API FOR ASTRAPAY END ======================================== //
}
