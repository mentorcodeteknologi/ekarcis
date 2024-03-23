<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Exception;

class BillingController extends Controller
{
    // ============================== //
    // FUNCTION INDEX
    // ============================== //
    public function index()
    {
        try {
            return "Billing Page";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }


    // ============================== //
    // FUNCTION BILLING NOTIFY
    // ============================== //
    public function billingNotify()
    {
        try {
            return "Billing Notify";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }


    // ============================== //
    // FUNCTION BILLING SUCCESS
    // ============================== //
    public function billingSuccess()
    {
        try {
            return "Billing Success";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }


    // ============================== //
    // FUNCTION BILLING FAILED
    // ============================== //
    public function billingFailed()
    {
        try {
            return "Billing Failed";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }


    // ============================== //
    // FUNCTION BILLING ERROR
    // ============================== //
    public function billingError()
    {
        try {
            return "Billing Error";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }


    // ============================== //
    // FUNCTION ACCESS TOKEN
    // ============================== //
    public function accessToken()
    {
        try {
            return "Access Token";
        } catch (Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }
}
