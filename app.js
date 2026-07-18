// Encryption & Crypto Functions
class CryptoManager {
  constructor() {
    this.keyPair = null;
    this.publicKey = null;
    this.secretKey = null;
    this.contactPublicKeys = new Map();
  }

  generateKeyPair() {
    const keyPair = nacl.box.keyPair();
    this.keyPair = keyPair;
    this.publicKey = nacl.util.encodeBase64(keyPair.publicKey);
    this.secretKey = nacl.util.encodeBase64(keyPair.secretKey);
    return {
      publicKey: this.publicKey,
      secretKey: this.secretKey
    };
  }

  encryptMessage(message, recipientPublicKeyBase64) {
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const messageUint8 = nacl.util.decodeUTF8(message);
    const recipientPublicKey = nacl.util.decodeBase64(recipientPublicKeyBase64);
    
    const encrypted = nacl.box(messageUint8, nonce, recipientPublicKey, this.keyPair.secretKey);
    
    return {
      encrypted: nacl.util.encodeBase64(encrypted),
      nonce: nacl.util.encodeBase64(nonce)
    };
  }

  decryptMessage(encryptedBase64, nonceBase64, senderPublicKeyBase64) {
    try {
      const encrypted = nacl.util.decodeBase64(encryptedBase64);
      const nonce = nacl.util.decodeBase64(nonceBase64);
      const senderPublicKey = nacl.util.decodeBase64(senderPublicKeyBase64);
      
      const decrypted = nacl.box.open(encrypted, nonce, senderPublicKey, this.keyPair.secretKey);
      
      if (!decrypted) {
        throw new Error('Failed to decrypt message');
      }
      
      return nacl.util.encodeUTF8(decrypted);
    } catch (err) {
      console.error('Decryption error:', err);
      return '[Unable to decrypt message]';
    }
  }

  addContactPublicKey(userId, publicKey) {
    this.contactPublicKeys.set(userId, publicKey);
  }

  getContactPublicKey(userId) {
    return this.contactPublicKeys.get(userId);
  }
}

// State Management
const state = {
  token: localStorage.getItem('token'),
  userId: localStorage.getItem('userId'),
  username: localStorage.getItem('username'),
  currentConversationId: null,
  currentRecipientId: null,
  currentRecipientName: null,
  conversations: [],
  users: [],
  ws: null,
  crypto: new CryptoManager(),
  isOnline: true
};

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  if (state.token) {
    await loadChat();
  } else {
    showAuthView();
  }

  // Detect online/offline
  window.addEventListener('online', () => {
    state.isOnline = true;
    updateStatusIndicator();
  });
  window.addEventListener('offline', () => {
    state.isOnline = false;
    updateStatusIndicator();
  });
});

// ==================== Authentication ====================

function toggleAuthForm() {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  loginForm.style.display = loginForm.style.display === 'none' ? 'block' : 'none';
  registerForm.style.display = registerForm.style.display === 'none' ? 'block' : 'none';
}

async function handleRegister() {
  const username = document.getElementById('regUsername').value.trim();
  const password = document.getElementById('regPassword').value;
  const errorEl = document.getElementById('regError');
  
  if (!username || !password) {
    showError(errorEl, 'Please fill in all fields');
    return;
  }

  if (password.length < 6) {
    showError(errorEl, 'Password must be at least 6 characters');
    return;
  }

  try {
    // Generate encryption keypair
    const keys = state.crypto.generateKeyPair();

    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        publicKey: keys.publicKey
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error);

    // Switch to login
    errorEl.classList.remove('show');
    toggleAuthForm();
    document.getElementById('loginUsername').value = username;
    
  } catch (err) {
    showError(errorEl, err.message);
  }
}

async function handleLogin() {
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errorEl = document.getElementById('loginError');

  if (!username || !password) {
    showError(errorEl, 'Please fill in all fields');
    return;
  }

  try {
    // Generate encryption keypair
    const keys = state.crypto.generateKeyPair();

    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        publicKey: keys.publicKey
      })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error);

    // Store credentials
    localStorage.setItem('token', data.token);
    localStorage.setItem('userId', data.userId);
    localStorage.setItem('username', data.username);
    
    state.token = data.token;
    state.userId = data.userId;
    state.username = data.username;

    await loadChat();
    
  } catch (err) {
    showError(errorEl, err.message);
  }
}

function showError(element, message) {
  element.textContent = message;
  element.classList.add('show');
}

// ==================== Chat Loading ====================

async function loadChat() {
  // Hide auth, show chat
  document.getElementById('authView').style.display = 'none';
  document.getElementById('chatView').style.display = 'flex';

  // Load users and conversations
  await loadUsers();
  await loadConversations();
  await connectWebSocket();
}

async function loadUsers() {
  try {
    const response = await fetch('/api/users', {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    
    if (!response.ok) throw new Error('Failed to load users');
    
    state.users = await response.json();
    state.users.forEach(user => {
      state.crypto.addContactPublicKey(user.id, user.public_key);
    });
  } catch (err) {
    console.error('Error loading users:', err);
  }
}

async function loadConversations() {
  try {
    const response = await fetch('/api/conversations', {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    
    if (!response.ok) throw new Error('Failed to load conversations');
    
    state.conversations = await response.json();
    renderConversationsList();
  } catch (err) {
    console.error('Error loading conversations:', err);
  }
}

function renderConversationsList() {
  const container = document.getElementById('conversationsList');
  
  if (state.conversations.length === 0) {
    container.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary); font-size: 13px;">No conversations yet</div>';
    return;
  }

  container.innerHTML = state.conversations.map(conv => `
    <div class="conversation-item ${conv.id === state.currentConversationId ? 'active' : ''}" 
         onclick="selectConversation(${conv.id}, ${conv.user_id}, '${conv.username}')">
      <div class="conversation-avatar">${conv.username.charAt(0).toUpperCase()}</div>
      <div class="conversation-info">
        <div class="conversation-name">${conv.username}</div>
        <div class="conversation-preview">Tap to open</div>
      </div>
    </div>
  `).join('');
}

// ==================== WebSocket ====================

function connectWebSocket() {
  return new Promise((resolve) => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}?token=${state.token}`;
    
    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      console.log('WebSocket connected');
      updateStatusIndicator();
      resolve();
    };

    state.ws.onmessage = (event) => {
      handleWebSocketMessage(JSON.parse(event.data));
    };

    state.ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      updateStatusIndicator();
    };

    state.ws.onclose = () => {
      console.log('WebSocket disconnected');
      updateStatusIndicator();
      // Attempt to reconnect in 3 seconds
      setTimeout(() => {
        if (state.token) connectWebSocket();
      }, 3000);
    };
  });
}

function handleWebSocketMessage(message) {
  if (message.type === 'new_message') {
    // Only show if this is the current conversation
    if (message.conversationId === state.currentConversationId) {
      const decrypted = state.crypto.decryptMessage(
        message.encryptedContent,
        message.nonce,
        state.crypto.getContactPublicKey(message.senderId)
      );

      appendMessage(message.senderId, decrypted, false);
    }
  }
}

function updateStatusIndicator() {
  const statusEl = document.getElementById('chatStatus');
  const statusDot = statusEl.querySelector('.status-dot');
  const statusText = document.getElementById('statusText');

  if (state.isOnline && state.ws?.readyState === WebSocket.OPEN) {
    statusDot.classList.add('online');
    statusText.textContent = 'Online';
  } else {
    statusDot.classList.remove('online');
    statusText.textContent = 'Offline';
  }
}

// ==================== Conversation Management ====================

async function selectConversation(conversationId, recipientId, recipientName) {
  state.currentConversationId = conversationId;
  state.currentRecipientId = recipientId;
  state.currentRecipientName = recipientName;

  // Update UI
  document.querySelectorAll('.conversation-item').forEach(el => {
    el.classList.remove('active');
  });
  event.target.closest('.conversation-item')?.classList.add('active');

  document.getElementById('chatTitle').textContent = recipientName;
  document.getElementById('chatStatus').style.display = 'flex';
  document.getElementById('inputArea').style.display = 'flex';

  // Load messages
  await loadMessages();
  
  // Scroll to bottom
  setTimeout(() => {
    const container = document.getElementById('messagesContainer');
    container.scrollTop = container.scrollHeight;
  }, 100);
}

async function loadMessages() {
  try {
    const response = await fetch(
      `/api/conversations/${state.currentConversationId}/messages`,
      { headers: { 'Authorization': `Bearer ${state.token}` } }
    );

    if (!response.ok) throw new Error('Failed to load messages');

    const messages = await response.json();
    renderMessages(messages);
  } catch (err) {
    console.error('Error loading messages:', err);
  }
}

function renderMessages(messages) {
  const container = document.getElementById('messagesContainer');
  container.innerHTML = '';

  messages.forEach(msg => {
    const decrypted = state.crypto.decryptMessage(
      msg.encrypted_content,
      msg.nonce,
      msg.sender_id === state.userId ? state.crypto.publicKey : state.crypto.getContactPublicKey(msg.sender_id)
    );

    const isSent = msg.sender_id === state.userId;
    const messageEl = document.createElement('div');
    messageEl.className = `message ${isSent ? 'sent' : 'received'}`;
    messageEl.innerHTML = `
      <div class="message-time">${new Date(msg.created_at).toLocaleTimeString()}</div>
      <div class="message-content">${escapeHtml(decrypted)}</div>
    `;
    container.appendChild(messageEl);
  });
}

// ==================== Messaging ====================

function sendMessage() {
  const input = document.getElementById('messageInput');
  const message = input.value.trim();

  if (!message || !state.currentRecipientId) return;

  try {
    // Encrypt message
    const recipientPublicKey = state.crypto.getContactPublicKey(state.currentRecipientId);
    const { encrypted, nonce } = state.crypto.encryptMessage(message, recipientPublicKey);

    // Send via WebSocket
    state.ws.send(JSON.stringify({
      type: 'send_message',
      recipientId: state.currentRecipientId,
      encryptedContent: encrypted,
      nonce: nonce
    }));

    // Show message locally
    appendMessage(state.userId, message, true);
    input.value = '';
    input.focus();
  } catch (err) {
    console.error('Error sending message:', err);
  }
}

function appendMessage(senderId, content, isSent) {
  const container = document.getElementById('messagesContainer');
  
  const messageEl = document.createElement('div');
  messageEl.className = `message ${isSent ? 'sent' : 'received'}`;
  
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  messageEl.innerHTML = `
    <div class="message-time">${now}</div>
    <div class="message-content">${escapeHtml(content)}</div>
  `;
  
  container.appendChild(messageEl);
  container.scrollTop = container.scrollHeight;
}

// Allow Enter to send
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey && document.getElementById('messageInput') === document.activeElement) {
    e.preventDefault();
    sendMessage();
  }
});

// ==================== New Chat Modal ====================

async function openNewChatModal() {
  const modal = document.getElementById('newChatModal');
  const usersList = document.getElementById('usersList');

  usersList.innerHTML = state.users.map(user => `
    <div class="user-item" onclick="startNewConversation(${user.id}, '${user.username}')">
      <div class="conversation-avatar">${user.username.charAt(0).toUpperCase()}</div>
      <div class="conversation-info">
        <div class="conversation-name">${user.username}</div>
      </div>
    </div>
  `).join('');

  modal.classList.add('show');
}

function closeNewChatModal() {
  document.getElementById('newChatModal').classList.remove('show');
}

async function startNewConversation(recipientId, recipientName) {
  closeNewChatModal();
  
  // Check if conversation already exists
  const existing = state.conversations.find(c => c.user_id === recipientId);
  if (existing) {
    selectConversation(existing.id, recipientId, recipientName);
    return;
  }

  // Create new conversation
  const newConv = {
    id: Date.now(),
    user_id: recipientId,
    username: recipientName
  };

  state.conversations.unshift(newConv);
  renderConversationsList();
  selectConversation(newConv.id, recipientId, recipientName);
}

// ==================== Utility Functions ====================

function showAuthView() {
  document.getElementById('authView').style.display = 'flex';
  document.getElementById('chatView').style.display = 'none';
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// Logout function (call this to clear and return to auth)
function logout() {
  localStorage.clear();
  location.reload();
}