package com.example.androidck;

import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;
import com.google.api.client.googleapis.services.GoogleClientRequestInitializer;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.playintegrity.v1.PlayIntegrity;
import com.google.api.services.playintegrity.v1.PlayIntegrityRequestInitializer;
import com.google.api.services.playintegrity.v1.PlayIntegrityScopes;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenRequest;
import com.google.api.services.playintegrity.v1.model.DecodeIntegrityTokenResponse;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class MainActivity extends AppCompatActivity {


    private void submitIntegrity(Map<String, String> message) {
        // create the NONCE  Base64-encoded, URL-safe, and non-wrapped String

        String myNonce = Base64.encodeToString((message.get("message") + "|" + message.get("signature")).getBytes(),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);

        // Create an instance of a manager.
        IntegrityManager myIntegrityManager = IntegrityManagerFactory.create(getApplicationContext());

        // Request the integrity token by providing a nonce.
        Task<IntegrityTokenResponse> myIntegrityTokenResponse = myIntegrityManager
                .requestIntegrityToken(IntegrityTokenRequest
                        .builder()
                        .setNonce(myNonce)
                        .setCloudProjectNumber(632149259757L)         // necessary only if sold outside Google Play
                        .build());

        // get the time to check against the decoded integrity token time
        long timeRequest = Calendar.getInstance().getTimeInMillis();

        myIntegrityTokenResponse.addOnFailureListener(e -> Log.d("AndroidCK", "Integrity token response: Failed: " + e));
        myIntegrityTokenResponse.addOnCompleteListener(e -> Log.d("AndroidCK", "Integrity token response: Complete: " + e));
        myIntegrityTokenResponse.addOnSuccessListener(myIntegrityTokenResponse1 -> {
            try {
                String token = myIntegrityTokenResponse1.token();

                DecodeIntegrityTokenRequest requestObj = new DecodeIntegrityTokenRequest();
                requestObj.setIntegrityToken(token);

                //Configure your credentials from the downloaded Json file from the resource
                AssetManager assetManager = getApplicationContext().getAssets();
                InputStream jsonStream = assetManager.open("credentials.json");
                GoogleCredentials credentials = GoogleCredentials.fromStream(jsonStream);
                GoogleCredentials scopedCredentials = credentials.createScoped(PlayIntegrityScopes.PLAYINTEGRITY);
                HttpRequestInitializer requestInitializer = new HttpCredentialsAdapter(scopedCredentials);

                HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
                JsonFactory JSON_FACTORY  = new JacksonFactory();
                GoogleClientRequestInitializer initializer = new PlayIntegrityRequestInitializer();

                PlayIntegrity.Builder playIntegrity = new PlayIntegrity.Builder(HTTP_TRANSPORT, JSON_FACTORY, requestInitializer).setApplicationName("your-project")
                        .setGoogleClientRequestInitializer(initializer);
                PlayIntegrity play = playIntegrity.build();

                // the DecodeIntegrityToken must be run on a parallel thread
                Thread thread = new Thread(() -> {
                    try  {
                        DecodeIntegrityTokenResponse response = play.v1().decodeIntegrityToken("com.project.name", requestObj).execute();
                        String licensingVerdict = response.getTokenPayloadExternal().getAccountDetails().getAppLicensingVerdict();
                        if (licensingVerdict.equalsIgnoreCase("LICENSED")) {
                            // Looks good! LICENSED app
                        } else {
                            // LICENSE NOT OK
                        }
                        Looper.prepare();
                        Toast toast = Toast.makeText(getApplicationContext(), "Response: " + licensingVerdict,
                                Toast.LENGTH_LONG);
                        toast.show();
                    } catch (Exception e) {
                        //  LICENSE error
                        Looper.prepare();
                        Toast toast = Toast.makeText(getApplicationContext(), "LICENSE ERROR",
                                Toast.LENGTH_LONG);
                        toast.show();
                        e.printStackTrace();
                    }
                });

                // execute the parallel thread
                thread.start();

            } catch (Error | Exception e) {
                // LICENSE error
                Toast toast = Toast.makeText(getApplicationContext(), "LICENSE ERROR 2",
                        Toast.LENGTH_LONG);
                toast.show();
                e.printStackTrace();
                System.out.println("ouch");
            }
        });

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button button = findViewById(R.id.goButton);
        button.setOnClickListener(view -> {
            EditText editTextPrivateKey = findViewById(R.id.editTextPrivateKey);
            String privateKey = editTextPrivateKey.getText().toString();

            try {
                Credentials credentials = Credentials.create(privateKey);
                String address = credentials.getAddress();
                /*Toast toast = Toast.makeText(getApplicationContext(), "Android CK: " + address,
                        Toast.LENGTH_LONG);
                toast.show();*/

                String nonceMessage = "AndroidCK " + new Random().nextInt();
                Sign.SignatureData signature = Sign.signPrefixedMessage(nonceMessage.getBytes(StandardCharsets.UTF_8),
                        credentials.getEcKeyPair());

                byte[] hexSignature = new byte[65];
                System.arraycopy(signature.getR(), 0, hexSignature, 0, 32);
                System.arraycopy(signature.getS(), 0, hexSignature, 32, 32);
                System.arraycopy(signature.getV(), 0, hexSignature, 64, 1);

                /*toast = Toast.makeText(getApplicationContext(), "Android CK: " + Numeric.toHexString(hexSignature),
                        Toast.LENGTH_LONG);
                toast.show();*/

                Map<String, String> map = new HashMap<String, String>() {{
                    put("message", nonceMessage);
                    put("signature", Numeric.toHexString(hexSignature));
                }};

                /*toast = Toast.makeText(getApplicationContext(), "Android CK: " + nonceMessage,
                        Toast.LENGTH_LONG);
                toast.show();*/

                System.out.println("Doing stuff");

                submitIntegrity(map);

            } catch (NumberFormatException e) {
                Toast toast = Toast.makeText(getApplicationContext(), "Android CK: " + e.getMessage(),
                        Toast.LENGTH_LONG);
                toast.show();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}