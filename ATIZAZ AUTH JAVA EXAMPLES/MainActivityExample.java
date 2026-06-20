package com.example.atizazauth;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONObject;

public class MainActivityExample extends AppCompatActivity {

    private AtizazAuthAPI api;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Example UI initialization would go here
        // setContentView(R.layout.activity_main);

        // 1. Setup API Details
        api = new AtizazAuthAPI(
                this, // Context is required for HWID (Settings.Secure.ANDROID_ID)
                "https://cmatizaz-cfire.atizazfayaz78.workers.dev",
                "ENTER SECRET",
                "ENTER NAME",
                "1.0"
        );

        // 2. Network operations must run in a background thread on Android
        new Thread(new Runnable() {
            @Override
            public void run() {
                // Initialize the SDK
                api.init();

                if (api.getSessionId() != null && !api.getSessionId().isEmpty()) {
                    Log.i("App", "Init Success! HWID: " + api.getHWID());
                    
                    // Example: Login
                    JSONObject response = api.login("testuser", "testpass");
                    
                    if (response != null && response.optBoolean("success", false)) {
                        String user = response.optString("username");
                        String expiry = response.optString("expiry");
                        
                        // Update UI on main thread
                        runOnUiThread(() -> {
                            Toast.makeText(MainActivityExample.this, "Welcome " + user + "! Expiry: " + expiry, Toast.LENGTH_LONG).show();
                        });
                    } else {
                        String error = response != null ? response.optString("message") : "Unknown Error";
                        runOnUiThread(() -> {
                            Toast.makeText(MainActivityExample.this, "Login Failed: " + error, Toast.LENGTH_LONG).show();
                        });
                    }
                }
            }
        }).start();
    }
}
