/// Web server example demonstrating nonce-auth in a multi-session environment.
///
/// This example showcases the thread-safe nature of CredentialVerifier (Send + Sync),
/// allowing it to be used directly in server environments without manual verification.
///
/// Key improvements:
/// - Direct use of CredentialVerifier instead of manual verification
/// - Proper storage sharing across requests for nonce replay protection
/// - Simplified code with better maintainability
use nonce_auth::{CredentialVerifier, storage::MemoryStorage, storage::NonceStorage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use warp::Filter;

#[derive(Deserialize)]
struct AuthenticatedRequest {
    payload: String,
    session_id: String,
    auth: nonce_auth::NonceCredential,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    data: Option<String>,
}

// Generate a cryptographically secure PSK using ChaCha20 CSPRNG
fn generate_psk() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32]; // 256-bit key
    rng.fill_bytes(&mut key);
    hex::encode(key)
}

// Function to generate HTML with embedded PSK and session ID
fn generate_html_with_psk_and_session(psk: &str, session_id: &str) -> String {
    format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Nonce Auth Demo</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .form-group {{
            margin-bottom: 15px;
        }}
        label {{
            display: block;
            margin: 15px 0 8px 0;
            font-weight: bold;
        }}
        textarea {{
            width: 100%;
            height: 70px;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            box-sizing: border-box;
        }}
        button {{
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 10px 20px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 10px 0;
            cursor: pointer;
            border-radius: 4px;
        }}
        button:disabled {{
            background-color: #cccccc;
            cursor: not-allowed;
        }}
        #result {{
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
            white-space: pre-wrap;
            font-family: monospace;
            min-height: 100px;
        }}
        .success {{
            background-color: #e8f5e9;
            border-left: 4px solid #4CAF50;
            padding: 10px;
        }}
        .error {{
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
        }}
        .info {{
            background-color: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 10px;
            margin-top: 15px;
        }}
    </style>
</head>
<body>
    <h1>Nonce Authentication Demo</h1>
    <p>Enter your message and click the button to test nonce authentication:</p>
    
    <div class="info">
        <h3>Current PSK (Pre-Shared Key):</h3>
        <div id="psk" style="font-family: monospace; word-break: break-all; background: #f5f5f5; padding: 10px; border-radius: 4px;">{psk}</div>
    </div>
    
    <div class="info">
        <h3>Signature Formula:</h3>
        <code>signature = HMAC-SHA256(psk, timestamp + nonce + payload)</code>
    </div>
    
    <div class="form-group">
        <label for="message">Payload:</label>
        <textarea id="message" placeholder="Enter your payload here...">Hello, secure world!</textarea>
    </div>
    
    <div class="form-group">
        <button id="testButton">Send Request</button>
        <button id="repeatButton" disabled>Repeat Last Request</button>
    </div>
    
    <div id="result">Click the button to send a request...</div>
    
    <div class="info">
        <h3>How to test:</h3>
        <ol>
            <li>Click "Send Request" to send a new request</li>
            <li>Click "Repeat Last Request" to send the same request again (should fail with "Nonce already used" error)</li>
            <li>Wait for the TTL (1 minute) to expire and try again</li>
        </ol>
    </div>

    <script>
        // PSK and session ID are embedded directly from server
        const currentPsk = '{psk}';
        const sessionId = '{session_id}';
        
        class NonceClient {{
            constructor(psk) {{
                // PSK is a hex string, convert it to bytes
                this.psk = new Uint8Array(psk.match(/.{{1,2}}/g).map(byte => parseInt(byte, 16)));
                this.lastRequest = null;
            }}

            async createSignedRequest(message) {{
                const timestamp = Math.floor(Date.now() / 1000);
                const nonce = this.generateUUID();
                const signature = await this.sign(timestamp.toString(), nonce, message);
                
                const request = {{
                    timestamp,
                    nonce,
                    signature
                }};
                
                // Save the last request for repeating
                this.lastRequest = {{ message, auth: {{...request}} }};
                
                return {{
                    payload: message,
                    session_id: sessionId,
                    auth: request
                }};
            }}

            async sign(timestamp, nonce, message) {{
                try {{
                    const key = await crypto.subtle.importKey(
                        'raw',
                        this.psk,
                        {{ name: 'HMAC', hash: 'SHA-256' }},
                        false,
                        ['sign']
                    );
                    
                    // Match the Rust server's MAC update pattern:
                    // mac.update(timestamp.to_string().as_bytes())
                    // mac.update(nonce.as_bytes())  
                    // mac.update(payload.as_bytes())
                    const encoder = new TextEncoder();
                    const timestampBytes = encoder.encode(timestamp.toString());
                    const nonceBytes = encoder.encode(nonce);
                    const messageBytes = encoder.encode(message);
                    
                    // Concatenate the byte arrays to match Rust's MAC.update() sequence
                    const totalLength = timestampBytes.length + nonceBytes.length + messageBytes.length;
                    const data = new Uint8Array(totalLength);
                    data.set(timestampBytes, 0);
                    data.set(nonceBytes, timestampBytes.length);
                    data.set(messageBytes, timestampBytes.length + nonceBytes.length);
                    
                    const signature = await crypto.subtle.sign('HMAC', key, data);
                    
                    // Convert to base64 to match Rust server expectation
                    const signatureArray = new Uint8Array(signature);
                    let binary = '';
                    for (let i = 0; i < signatureArray.byteLength; i++) {{
                        binary += String.fromCharCode(signatureArray[i]);
                    }}
                    return btoa(binary);
                }} catch (error) {{
                    console.error('Signing failed:', error);
                    throw error;
                }}
            }}

            generateUUID() {{
                return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {{
                    const r = Math.random() * 16 | 0;
                    const v = c === 'x' ? r : (r & 0x3 | 0x8);
                    return v.toString(16);
                }});
            }}
        }}

        // Initialize client with embedded PSK
        const client = new NonceClient(currentPsk);
        let lastResponse = null;

        async function sendRequest(requestData) {{
            const resultDiv = document.getElementById('result');
            const testButton = document.getElementById('testButton');
            const repeatButton = document.getElementById('repeatButton');
            
            try {{
                testButton.disabled = true;
                repeatButton.disabled = true;
                
                // Show the request data before sending
                const requestInfo = `=== Request Data ===\n${{JSON.stringify(requestData, null, 2)}}\n\nSending request...`;
                resultDiv.textContent = requestInfo;
                resultDiv.className = '';

                const response = await fetch('/api/protected', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(requestData)
                }});
                
                const result = await response.json();
                lastResponse = result;
                
                // Show both request and response
                const responseInfo = `=== Request Data ===\n${{JSON.stringify(requestData, null, 2)}}\n\n=== Response (${{response.status}}) ===\n${{JSON.stringify(result, null, 2)}}`;
                resultDiv.textContent = responseInfo;
                resultDiv.className = result.success ? 'success' : 'error';
                
                // Enable repeat button if we have a last request
                if (client.lastRequest) {{
                    repeatButton.disabled = false;
                }}
            }} catch (error) {{
                const errorInfo = `=== Request Data ===\n${{JSON.stringify(requestData, null, 2)}}\n\n=== Error ===\n${{error.message || 'Unknown error'}}`;
                resultDiv.textContent = errorInfo;
                resultDiv.className = 'error';
                console.error('Request failed:', error);
            }} finally {{
                testButton.disabled = false;
            }}
        }}

        document.getElementById('testButton').addEventListener('click', async () => {{
            const message = document.getElementById('message').value.trim() || 'Hello, secure world!';
            const requestData = await client.createSignedRequest(message);
            await sendRequest(requestData);
        }});

        document.getElementById('repeatButton').addEventListener('click', async () => {{
            if (client.lastRequest) {{
                // Create a new request with the same message and auth data
                const repeatRequest = {{
                    payload: client.lastRequest.message,
                    session_id: sessionId,
                    auth: {{...client.lastRequest.auth}}
                }};
                await sendRequest(repeatRequest);
            }}
        }});
    </script>
</body>
</html>
"#
    )
}

// Store PSKs and storage backends for each session
type PskStore = Arc<std::sync::Mutex<HashMap<String, String>>>;
type StorageStore = Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn NonceStorage>>>>;

#[tokio::main]
async fn main() {
    // Create PSK store and storage store
    let psk_store: PskStore = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let storage_store: StorageStore = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Serve index.html at the root path with embedded PSK
    let psk_store_filter = warp::any().map(move || psk_store.clone());
    let storage_store_filter = warp::any().map(move || storage_store.clone());
    let index_route = warp::path::end()
        .and(psk_store_filter.clone())
        .and(storage_store_filter.clone())
        .and_then(handle_index_request);

    // Protected API route
    let protected_route = warp::path("api")
        .and(warp::path("protected"))
        .and(warp::post())
        .and(warp::body::json())
        .and(psk_store_filter)
        .and(storage_store_filter)
        .and_then(handle_protected_request);

    // Combine routes
    let routes = index_route.or(protected_route).with(
        warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(vec!["GET", "POST"]),
    );

    println!("Server running on http://localhost:3000");
    println!("Open this URL in your browser to test the authentication");
    println!("Each page refresh will generate a new PSK");

    warp::serve(routes).run(([127, 0, 0, 1], 3000)).await;
}

async fn handle_index_request(
    psk_store: PskStore,
    storage_store: StorageStore,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Generate a new PSK and session ID for this page load
    let psk = generate_psk();
    let session_id = generate_psk(); // Use same function for session ID

    // Store the PSK using session ID as the key
    {
        let mut store = psk_store.lock().unwrap();
        store.insert(session_id.clone(), psk.clone());
        println!("Stored PSK for session ID: {session_id}");
    }

    // Clean up the storage for this session (if it exists)
    {
        let mut storages = storage_store.lock().await;
        storages.remove(&session_id);
    }

    // Generate HTML with embedded PSK and session ID
    let html = generate_html_with_psk_and_session(&psk, &session_id);
    Ok(warp::reply::html(html))
}

async fn handle_protected_request(
    req: AuthenticatedRequest,
    psk_store: PskStore,
    storage_store: StorageStore,
) -> Result<impl warp::Reply, warp::Rejection> {
    // Get the PSK from store using session ID
    let psk = {
        let store = psk_store.lock().unwrap();
        println!("Looking for session ID: {}", req.session_id);
        store.get(&req.session_id).cloned()
    };

    let psk = match psk {
        Some(psk) => psk,
        None => {
            let response = ApiResponse {
                success: false,
                message: "Invalid session ID. Please refresh the page.".to_string(),
                data: None,
            };
            return Ok(warp::reply::json(&response));
        }
    };

    // Get or create the storage for this session
    let storage = {
        let mut storages = storage_store.lock().await;
        match storages.get(&req.session_id) {
            Some(storage) => storage.clone(),
            None => {
                // Create a new storage for this session
                let new_storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
                new_storage
                    .init()
                    .await
                    .expect("Failed to initialize storage");
                storages.insert(req.session_id.clone(), new_storage.clone());
                new_storage
            }
        }
    };

    // Convert hex PSK to bytes
    let psk_bytes = hex::decode(&psk)
        .inspect_err(|e| {
            println!("Failed to decode PSK: {e}");
        })
        .unwrap_or_else(|_| psk.as_bytes().to_vec());

    // Use CredentialVerifier directly (now supports Sync!)
    let result = CredentialVerifier::new(storage)
        .with_secret(&psk_bytes)
        .with_time_window(Duration::from_secs(15))
        .with_storage_ttl(Duration::from_secs(60))
        .verify(&req.auth, req.payload.as_bytes())
        .await;

    match result {
        Ok(()) => {
            let response = ApiResponse {
                success: true,
                message: "Request authenticated successfully".to_string(),
                data: Some(format!("Processed: {}", req.payload)),
            };
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = ApiResponse {
                success: false,
                message: format!("Authentication failed: {e:?}"),
                data: None,
            };
            Ok(warp::reply::json(&response))
        }
    }
}
