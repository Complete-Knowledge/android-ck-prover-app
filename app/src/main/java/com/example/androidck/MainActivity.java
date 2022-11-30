package com.example.androidck;

import android.content.res.AssetManager;
import android.os.Bundle;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
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
import com.google.api.services.playintegrity.v1.model.TokenPayloadExternal;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.SecretKeyFactory;

public class MainActivity extends AppCompatActivity {

    private void getKeystore(byte[] challenge) throws KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertificateException {
        // Create KeyPairGenerator and set generation parameters for an ECDSA key pair
        // using the NIST P-256 curve.  "Key1" is the key alias.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder("Key1", KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256,
                                KeyProperties.DIGEST_SHA384,
                                KeyProperties.DIGEST_SHA512)
                        // Only permit the private key to be used if the user
                        // authenticated within the last five minutes.
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(5 * 60)
                        // Request an attestation with challenge "hello world".
                        .setAttestationChallenge(challenge)
                        .build());
        // Generate the key pair. This will result in calls to both generate_key() and
        // attest_key() at the keymaster2 HAL.
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // Get the certificate chain
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Certificate[] certs = keyStore.getCertificateChain("Key1");
        // certs[0] is the attestation certificate. certs[1] signs certs[0], etc.,
        // up to certs[certs.length - 1].
        Log.d("CKVerifier", certs.toString());
        Log.d("CKVerifier", "Certs length: " + certs.length);
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            Log.d("CKVerifier", "Cert " + i + ": " + cert.getIssuerDN());
            Log.d("CKVerifier", "Complete cert: " + Numeric.toHexString(cert.getEncoded()));
            Log.d("CKVerifier", cert.getSigAlgName());
            Log.d("CKVerifier", cert.toString());
            //Log.d("CKVerifier", cert.getSig());
            if (i > 0) {
                continue;
            }
            byte[] attestationExtensionBytes = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
            ASN1Primitive decodedSequence;
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
                // The extension contains one object, a sequence, in the
                // Distinguished Encoding Rules (DER)-encoded form. Get the DER
                // bytes.
                byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
                // Decode the bytes as an ASN1 sequence object.
                try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
                    decodedSequence = (ASN1Primitive) seqInputStream.readObject();
                }
            }
            Log.d("CKVerifier", String.valueOf(decodedSequence));
            Log.d("CKVerifier", ASN1Dump.dumpAsString(decodedSequence));
        }
    }

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
                        Log.d("Android CK", requestObj.toPrettyString());
                        Log.d("Android CK", requestObj.getIntegrityToken());
                        DecodeIntegrityTokenResponse response = play.v1().decodeIntegrityToken("com.project.name", requestObj).execute();
                        Log.d("Android CK", response.toPrettyString());
                        TokenPayloadExternal payloadExternal = response.getTokenPayloadExternal();
                        String licensingVerdict = payloadExternal.getAccountDetails().getAppLicensingVerdict();
                        if (licensingVerdict.equalsIgnoreCase("LICENSED")) {
                            // Looks good! LICENSED app
                        } else {
                            // LICENSE NOT OK
                        }
                        Log.d("Android CK", "Request details: " + String.valueOf(payloadExternal.getRequestDetails().toPrettyString()));
                        Log.d("Android CK", "Application integrity: " + String.valueOf(payloadExternal.getAppIntegrity().toPrettyString()));
                        Log.d("Android CK", "Device integrity: " + String.valueOf(payloadExternal.getDeviceIntegrity().getDeviceRecognitionVerdict()));
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
                getKeystore(hexSignature);
                //submitIntegrity(map);

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