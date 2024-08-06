<?php

namespace App\Helpers;

class ResponseFormatter
{

    // ========================== //
    // FUNCTION RESPONSE          //
    // ========================== //
    protected static $response = [
        'responseCode'    => 2007300,
        'responseMessage' => "Successful",
    ];


    // ========================== //
    //  FUNCTION FOR SUCCESS DATA //
    // ========================== //
    public static function success($data = [], $code = 200)
    {
        self::$response = array_merge(self::$response, $data);

        return response()->json(self::$response, $code);
    }



    // ========================== //
    //  FUNCTION FOR ERROR DATA   //
    // ========================== //
    public static function error($message = null, $responseCode = 4005800)
    {
        self::$response['responseCode']    = $responseCode;
        self::$response['responseMessage'] = $message;

        return response()->json(self::$response, substr($responseCode, 0, 3));
    }

    // ============================ //
    //  FUNCTION FOR ERROR DATA V1  //
    // ============================ //
    public static function errorV1($message = null, $responseCode = 400, $serviceCode = 58, $caseCode = 00)
    {
        self::$response['responseCode']    = $serviceCode . $caseCode . $responseCode;
        self::$response['responseMessage'] = $message;

        return response()->json(self::$response, $responseCode);
    }
}
