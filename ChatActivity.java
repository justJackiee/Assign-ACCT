package com.example.securechat;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.example.securechat.CryptoManager;
import com.example.securechat.crypto.AlgorithmSelector;
import com.example.securechat.crypto.SignatureBase;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes4.dex */
public class ChatActivity extends AppCompatActivity {
    private static final String BASE_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev";
    private static final String HOSTNAME = "crypto-assignment.dangduongminhnhat2003.workers.dev";
    private static final String SPKI_BASE64 = "LLarg8tqQEn0O1lsHVG6pyTY/WtrtilDwKj8ZRwTWeI=";
    private static final String TAG = "ChatActivity";
    private String algorithmName;
    private OkHttpClient client;
    private CryptoManager cryptoManager;
    private boolean freshLogin;
    private EditText inputMessage;
    private Button logoutButton;
    private MessageAdapter messageAdapter;
    private List<Message> messages;
    private RecyclerView messagesRecyclerView;
    private ProgressDialog progressDialog;
    private Button sendButton;
    private String sessionToken;
    private TextView statusText;
    private String userId;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);
        initViews();
        setupRecyclerView();
        this.userId = getIntent().getStringExtra("userId");
        this.sessionToken = getIntent().getStringExtra("sessionToken");
        this.algorithmName = getIntent().getStringExtra("algorithmName");
        this.freshLogin = getIntent().getBooleanExtra("freshLogin", false);
        if (this.userId == null || this.sessionToken == null) {
            Toast.makeText(this, "Invalid session data", 0).show();
            finish();
            return;
        }
        this.client = buildClient();
        this.cryptoManager = CryptoSingleton.getInstance().getCryptoManager();
        if (this.freshLogin && CryptoSingleton.getInstance().isReady()) {
            setStatusText("Connected & Encrypted (" + this.algorithmName + ")");
            showWelcomeMessages(true, this.algorithmName);
        } else {
            showProgress("Verifying session...");
            verifyRestoredSession();
        }
        this.sendButton.setOnClickListener(new View.OnClickListener() { // from class: com.example.securechat.ChatActivity$$ExternalSyntheticLambda2
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.m57lambda$onCreate$0$comexamplesecurechatChatActivity(view);
            }
        });
        this.logoutButton.setOnClickListener(new View.OnClickListener() { // from class: com.example.securechat.ChatActivity$$ExternalSyntheticLambda3
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws JSONException {
                this.f$0.m58lambda$onCreate$1$comexamplesecurechatChatActivity(view);
            }
        });
    }

    /* renamed from: lambda$onCreate$0$com-example-securechat-ChatActivity, reason: not valid java name */
    /* synthetic */ void m57lambda$onCreate$0$comexamplesecurechatChatActivity(View v) throws JSONException {
        String message = this.inputMessage.getText().toString().trim();
        if (message.isEmpty()) {
            return;
        }
        sendMessage(message);
        this.inputMessage.setText(HttpUrl.FRAGMENT_ENCODE_SET);
    }

    /* renamed from: lambda$onCreate$1$com-example-securechat-ChatActivity, reason: not valid java name */
    /* synthetic */ void m58lambda$onCreate$1$comexamplesecurechatChatActivity(View v) throws JSONException {
        logout();
    }

    private void initViews() {
        this.inputMessage = (EditText) findViewById(R.id.inputMessage);
        this.sendButton = (Button) findViewById(R.id.sendButton);
        this.logoutButton = (Button) findViewById(R.id.logoutButton);
        this.statusText = (TextView) findViewById(R.id.statusText);
        this.messagesRecyclerView = (RecyclerView) findViewById(R.id.messagesRecyclerView);
    }

    private void setupRecyclerView() {
        this.messages = new ArrayList();
        this.messageAdapter = new MessageAdapter(this.messages);
        this.messagesRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.messagesRecyclerView.setAdapter(this.messageAdapter);
    }

    private void verifyRestoredSession() {
        Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/status?token=" + this.sessionToken + "&userId=" + this.userId).addHeader("x-user-id", this.userId).get().build();
        this.client.newCall(request).enqueue(new AnonymousClass1());
    }

    /* renamed from: com.example.securechat.ChatActivity$1, reason: invalid class name */
    class AnonymousClass1 implements Callback {
        AnonymousClass1() {
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, IOException e) {
            ChatActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$1$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.m60lambda$onFailure$0$comexamplesecurechatChatActivity$1();
                }
            });
        }

        /* renamed from: lambda$onFailure$0$com-example-securechat-ChatActivity$1, reason: not valid java name */
        /* synthetic */ void m60lambda$onFailure$0$comexamplesecurechatChatActivity$1() {
            ChatActivity.this.hideProgress();
            ChatActivity.this.showError("Session verification failed. Please login again.");
            ChatActivity.this.finish();
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, final Response response) throws IOException {
            final String responseBody = response.body().string();
            ChatActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$1$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws JSONException {
                    this.f$0.m61lambda$onResponse$1$comexamplesecurechatChatActivity$1(response, responseBody);
                }
            });
        }

        /* renamed from: lambda$onResponse$1$com-example-securechat-ChatActivity$1, reason: not valid java name */
        /* synthetic */ void m61lambda$onResponse$1$comexamplesecurechatChatActivity$1(Response response, String responseBody) throws JSONException {
            ChatActivity.this.hideProgress();
            if (response.isSuccessful()) {
                try {
                    JSONObject result = new JSONObject(responseBody);
                    if (!result.getBoolean("success")) {
                        ChatActivity.this.showError("Session verification failed. Please login again.");
                        ChatActivity.this.finish();
                        return;
                    }
                    boolean exists = result.getBoolean("exists");
                    String serverAlgorithm = result.optString("algorithm", "Unknown");
                    if (exists) {
                        ChatActivity.this.setStatusText("Connected (Session Restored - " + serverAlgorithm + ")");
                        ChatActivity.this.showWelcomeMessages(false, serverAlgorithm);
                        return;
                    } else {
                        ChatActivity.this.showError("Session expired. Please login again.");
                        ChatActivity.this.clearSavedCredentials();
                        ChatActivity.this.finish();
                        return;
                    }
                } catch (Exception e) {
                    ChatActivity.this.showError("Invalid session response. Please login again.");
                    ChatActivity.this.finish();
                    return;
                }
            }
            ChatActivity.this.showError("Session verification failed. Please login again.");
            ChatActivity.this.finish();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setStatusText(final String status) {
        runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$$ExternalSyntheticLambda4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.m59lambda$setStatusText$2$comexamplesecurechatChatActivity(status);
            }
        });
    }

    /* renamed from: lambda$setStatusText$2$com-example-securechat-ChatActivity, reason: not valid java name */
    /* synthetic */ void m59lambda$setStatusText$2$comexamplesecurechatChatActivity(String status) {
        this.statusText.setText("Status: " + status);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addMessage(final String content, final boolean isFromUser) {
        runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$$ExternalSyntheticLambda1
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.m55lambda$addMessage$3$comexamplesecurechatChatActivity(content, isFromUser);
            }
        });
    }

    /* renamed from: lambda$addMessage$3$com-example-securechat-ChatActivity, reason: not valid java name */
    /* synthetic */ void m55lambda$addMessage$3$comexamplesecurechatChatActivity(String content, boolean isFromUser) {
        this.messages.add(new Message(content, isFromUser, System.currentTimeMillis()));
        this.messageAdapter.notifyItemInserted(this.messages.size() - 1);
        this.messagesRecyclerView.scrollToPosition(this.messages.size() - 1);
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder().connectTimeout(15L, TimeUnit.SECONDS).readTimeout(30L, TimeUnit.SECONDS);
        if (0 == 0) {
            Log.d("SSL Pinning", "Have Pinning Here");
            CertificatePinner pinner = new CertificatePinner.Builder().add(HOSTNAME, "sha256/LLarg8tqQEn0O1lsHVG6pyTY/WtrtilDwKj8ZRwTWeI=").build();
            builder.certificatePinner(pinner);
        }
        return builder.build();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showWelcomeMessages(boolean isFreshLogin, String algorithm) {
        if (isFreshLogin && CryptoSingleton.getInstance().isReady()) {
            addMessage("🔒 Secure connection established", false);
            addMessage("🔐 Algorithm: " + algorithm, false);
            addMessage("✅ Full end-to-end encryption active", false);
        } else {
            addMessage("🔄 Session restored", false);
            addMessage("🔐 Algorithm: " + algorithm, false);
            addMessage("⚠️ Limited functionality - login again for full E2E encryption", false);
        }
        addMessage("You can ask me about: name, age, location, hobby", false);
    }

    private void sendMessage(String message) throws JSONException {
        if (!CryptoSingleton.getInstance().isReady()) {
            addMessage("❌ Encryption not available", false);
            return;
        }
        try {
            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", this.sessionToken);
            try {
                if ("ecdh_3".equals(AlgorithmSelector.getAlgorithmForUser(this.userId))) {
                    this.cryptoManager.setEncryptionMode("CBC");
                }
                String encryptedMessage = this.cryptoManager.encrypt(message);
                requestBody.put("encryptedMessage", encryptedMessage);
                if (this.cryptoManager.isSignatureSupported()) {
                    try {
                        Log.d(TAG, "Signing message with EPHEMERAL key...");
                        CryptoManager.SignatureWithPublicKey signResult = this.cryptoManager.signMessageEphemeral(encryptedMessage);
                        requestBody.put("messageSignature", signResult.signature.toJSON());
                        requestBody.put("clientSignaturePublicKey", signResult.publicKey);
                        Log.d(TAG, "✅ Message signed with EPHEMERAL key");
                        RequestBody body = RequestBody.create(requestBody.toString(), MediaType.parse("application/json"));
                        Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/message/send?userId=" + this.userId).addHeader("x-user-id", this.userId).post(body).build();
                        addMessage(message, true);
                        this.client.newCall(request).enqueue(new AnonymousClass2());
                        return;
                    } catch (Exception e) {
                        addMessage("❌ Failed to sign: " + e.getMessage(), false);
                        return;
                    }
                }
                addMessage("❌ Signature not supported", false);
            } catch (Exception e2) {
                addMessage("❌ Encryption failed", false);
            }
        } catch (Exception e3) {
            addMessage("❌ Error: " + e3.getMessage(), false);
        }
    }

    /* renamed from: com.example.securechat.ChatActivity$2, reason: invalid class name */
    class AnonymousClass2 implements Callback {
        AnonymousClass2() {
        }

        /* renamed from: lambda$onFailure$0$com-example-securechat-ChatActivity$2, reason: not valid java name */
        /* synthetic */ void m62lambda$onFailure$0$comexamplesecurechatChatActivity$2() {
            ChatActivity.this.addMessage("❌ Send failed", false);
        }

        @Override // okhttp3.Callback
        public void onFailure(Call call, IOException e) {
            ChatActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$2$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.m62lambda$onFailure$0$comexamplesecurechatChatActivity$2();
                }
            });
        }

        @Override // okhttp3.Callback
        public void onResponse(Call call, final Response response) throws IOException {
            final String responseBody = response.body().string();
            ChatActivity.this.runOnUiThread(new Runnable() { // from class: com.example.securechat.ChatActivity$2$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() throws JSONException {
                    this.f$0.m63lambda$onResponse$1$comexamplesecurechatChatActivity$2(response, responseBody);
                }
            });
        }

        /* renamed from: lambda$onResponse$1$com-example-securechat-ChatActivity$2, reason: not valid java name */
        /* synthetic */ void m63lambda$onResponse$1$comexamplesecurechatChatActivity$2(Response response, String responseBody) throws JSONException {
            if (response.isSuccessful()) {
                try {
                    JSONObject jsonResponse = new JSONObject(responseBody);
                    if (!jsonResponse.getBoolean("success")) {
                        ChatActivity.this.addMessage("❌ " + jsonResponse.optString("error"), false);
                        return;
                    }
                    String newToken = jsonResponse.optString("sessionToken", null);
                    if (newToken != null) {
                        ChatActivity.this.sessionToken = newToken;
                        ChatActivity.this.getSharedPreferences("SecureChat", 0).edit().putString("sessionToken", ChatActivity.this.sessionToken).apply();
                    }
                    if (jsonResponse.has("responseSignature") && jsonResponse.has("serverSignaturePublicKey")) {
                        String encryptedResponse = jsonResponse.getString("encryptedResponse");
                        JSONObject respSigJson = jsonResponse.getJSONObject("responseSignature");
                        JSONObject serverEphemeralPubKey = jsonResponse.getJSONObject("serverSignaturePublicKey");
                        Log.d(ChatActivity.TAG, "Verifying response with server's EPHEMERAL public key...");
                        try {
                            SignatureBase.Signature respSignature = SignatureBase.Signature.fromJSON(respSigJson, ChatActivity.this.cryptoManager.getSignatureAlgorithmName());
                            boolean verified = ChatActivity.this.cryptoManager.verifySignatureWithPublicKey(encryptedResponse, respSignature, serverEphemeralPubKey);
                            if (!verified) {
                                Log.e(ChatActivity.TAG, "❌ Response signature verification FAILED");
                                ChatActivity.this.addMessage("❌ SECURITY ALERT: Invalid signature!", false);
                                return;
                            }
                            Log.d(ChatActivity.TAG, "✅ Response signature verified (EPHEMERAL key)");
                            try {
                                if ("ecdh_3".equals(AlgorithmSelector.getAlgorithmForUser(ChatActivity.this.userId))) {
                                    ChatActivity.this.cryptoManager.setEncryptionMode("CBC");
                                }
                                String decryptedResponse = ChatActivity.this.cryptoManager.decrypt(encryptedResponse);
                                ChatActivity.this.addMessage(decryptedResponse, false);
                                return;
                            } catch (Exception e) {
                                ChatActivity.this.addMessage("❌ Decryption failed", false);
                                return;
                            }
                        } catch (Exception e2) {
                            ChatActivity.this.addMessage("❌ Signature verification error", false);
                            return;
                        }
                    }
                    ChatActivity.this.addMessage("❌ Server response not signed!", false);
                    return;
                } catch (Exception e3) {
                    ChatActivity.this.addMessage("❌ Error: " + e3.getMessage(), false);
                    return;
                }
            }
            ChatActivity.this.handleServerError(response.code(), responseBody);
        }
    }

    private void showProgress(String message) {
        if (this.progressDialog == null) {
            this.progressDialog = new ProgressDialog(this);
            this.progressDialog.setCancelable(false);
        }
        this.progressDialog.setMessage(message);
        this.progressDialog.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideProgress() {
        if (this.progressDialog != null && this.progressDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError(String message) {
        new AlertDialog.Builder(this).setTitle("Error").setMessage(message).setPositiveButton("OK", (DialogInterface.OnClickListener) null).setIcon(android.R.drawable.ic_dialog_alert).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleServerError(int statusCode, String responseBody) throws JSONException {
        String errorMessage = "Server error: " + statusCode;
        try {
            JSONObject errorJson = new JSONObject(responseBody);
            if (errorJson.has("error")) {
                errorMessage = errorJson.getString("error");
            }
        } catch (Exception e) {
        }
        switch (statusCode) {
            case 400:
                if (errorMessage.contains("Missing required fields")) {
                    errorMessage = "Missing required fields - check encryption";
                    break;
                }
                break;
            case TypedValues.CycleType.TYPE_ALPHA /* 403 */:
                errorMessage = "Access forbidden";
                break;
            case 404:
                logout();
                return;
            case 429:
                errorMessage = "Daily quota exceeded";
                break;
            case 430:
                errorMessage = "Too many requests per minute";
                break;
        }
        addMessage("❌ " + errorMessage, false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clearSavedCredentials() {
        CryptoSingleton.getInstance().clear();
        SharedPreferences prefs = getSharedPreferences("SecureChat", 0);
        prefs.edit().clear().apply();
    }

    private void logout() throws JSONException {
        try {
            JSONObject requestBody = new JSONObject();
            requestBody.put("sessionToken", this.sessionToken);
            RequestBody body = RequestBody.create(requestBody.toString(), MediaType.parse("application/json"));
            Request request = new Request.Builder().url("https://crypto-assignment.dangduongminhnhat2003.workers.dev/session/delete?userId=" + this.userId).addHeader("x-user-id", this.userId).post(body).build();
            this.client.newCall(request).enqueue(new Callback() { // from class: com.example.securechat.ChatActivity.3
                @Override // okhttp3.Callback
                public void onFailure(Call call, IOException e) {
                    Log.d(ChatActivity.TAG, "Session deletion failed (server might be down)");
                }

                @Override // okhttp3.Callback
                public void onResponse(Call call, Response response) {
                    Log.d(ChatActivity.TAG, "Session deleted on server");
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Error deleting session", e);
        }
        clearSavedCredentials();
        finish();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        new AlertDialog.Builder(this).setTitle("Logout").setMessage("Do you want to logout?").setPositiveButton("Yes", new DialogInterface.OnClickListener() { // from class: com.example.securechat.ChatActivity$$ExternalSyntheticLambda0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) throws JSONException {
                this.f$0.m56lambda$onBackPressed$4$comexamplesecurechatChatActivity(dialogInterface, i);
            }
        }).setNegativeButton("No", (DialogInterface.OnClickListener) null).show();
    }

    /* renamed from: lambda$onBackPressed$4$com-example-securechat-ChatActivity, reason: not valid java name */
    /* synthetic */ void m56lambda$onBackPressed$4$comexamplesecurechatChatActivity(DialogInterface dialog, int which) throws JSONException {
        logout();
    }
}