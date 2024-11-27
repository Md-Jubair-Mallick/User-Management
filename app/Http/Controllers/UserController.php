<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rule;

class UserController extends Controller
{
    /**
     * Handles the user signup logic.
     */
    public function signup(Request $request)
    {
        // Validation rules
        $rules = [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => [
                'required',
                'string',
                'min:8', // Minimum 8 characters
                'regex:/[A-Z]/', // At least one uppercase letter
                'regex:/[a-z]/', // At least one lowercase letter
                'regex:/[0-9]/', // At least one number
                'regex:/[@$!%*?&#]/', // At least one special character
            ],
        ];

        // Validate the request
        $validator = Validator::make($request->all(), $rules, [
            'password.regex' => 'The password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        // Prepare user data
        $input = $request->only(['name', 'email', 'password']);
        $input['password'] = Hash::make($input['password']);

        try {
            $user = User::create($input);

            // Generate Sanctum token
            $token = $user->createToken('authToken')->plainTextToken;

            return response()->json([
                'success' => true,
                'message' => 'User signed up successfully.',
                'result' => $user,
                'token' => $token,
            ], 201);
        } catch (\Exception $e) {
            // Log the error for debugging
            Log::error('Signup failed', ['error' => $e->getMessage()]);

            return response()->json([
                'success' => false,
                'message' => 'User signup failed. Please try again later.',
            ], 500);
        }
    }

    /**
     * Handles the user login logic.
     */
    public function login(Request $request)
    {
        // Validation rules
        $rules = [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ];

        // Validate the request
        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors(),
            ], 422);
        }

        // Rate limiting logic
        $ip = $request->ip();
        $key = "login_attempts:{$ip}";
        $maxAttempts = 5; // Maximum allowed attempts
        $decayMinutes = 15; // Time before attempts reset

        if (cache()->get($key, 0) >= $maxAttempts) {
            return response()->json([
                'success' => false,
                'message' => 'Too many login attempts. Please try again later.',
            ], 429); // HTTP 429 Too Many Requests
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            // Increment login attempts on failure
            cache()->increment($key);
            cache()->put($key, cache()->get($key, 1), now()->addMinutes($decayMinutes));

            return response()->json([
                'success' => false,
                'message' => 'Invalid email or password.',
            ], 401); // HTTP 401 Unauthorized
        }

        // Reset login attempts on success
        cache()->forget($key);

        // Create and return token
        $token = $user->createToken('authToken')->plainTextToken;

        return response()->json([
            'success' => true,
            'message' => 'User logged in successfully.',
            'token' => $token,
        ], 200); // HTTP 200 OK
    }

}
