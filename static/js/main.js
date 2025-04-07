// Global Variables
let webhookToken = null;
let currentWebhookUrl = null;  // Store current webhook URL in memory only

// Add webhook URL storage in memory (not localStorage)
let webhookUrl = null;

// Add new variable to track search state
let isInSearchMode = false;
let lastSearchTerm = '';

// Document Ready
document.addEventListener('DOMContentLoaded', async (event) => {
    try {
        // Load saved webhook URL from localStorage
        const storedWebhookUrl = localStorage.getItem('webhook_url');
        const input = document.getElementById('webhook_url');
        
        if (storedWebhookUrl) {
            // Set the input value
            input.value = storedWebhookUrl;
            // Store in memory
            currentWebhookUrl = storedWebhookUrl;
            webhookUrl = storedWebhookUrl;
            
            // Get webhook token and refresh files
            await getWebhookToken();
            await refreshFileList();
            
            // Lock the input
            lockWebhookInput();
        }
        
        // Lock webhook input by default even if empty
        if (!input.value) {
            lockWebhookInput();
        }

        // Setup search input dengan pencegahan autofill
        const searchInput = document.getElementById('search_input');
        if (searchInput) {
            // Reset search input value
            searchInput.value = '';
            
            // Prevent autofill/autocomplete
            searchInput.setAttribute('autocomplete', 'off');
            searchInput.setAttribute('data-lpignore', 'true');
            
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    searchFiles(e);
                }
            });

            // Clear search results when input is empty
            searchInput.addEventListener('input', debounce(async (e) => {
                const query = e.target.value.trim();
                if (!query) {
                    const searchLabel = document.querySelector('.recent-files-label');
                    searchLabel.innerHTML = '<i class="fas fa-clock"></i> Recent Files';
                    window.currentSearchTerm = '';
                    isInSearchMode = false;
                    lastSearchTerm = '';
                    await refreshFileList(); // Refresh to show all files
                }
            }, 300));

            // Prevent paste of webhook URL
            searchInput.addEventListener('paste', (e) => {
                const pastedText = (e.clipboardData || window.clipboardData).getData('text');
                if (pastedText.includes('discord.com/api/webhooks')) {
                    e.preventDefault();
                }
            });
        }
    } catch (error) {
        console.error('Initialization error:', error);
        showAlert('Failed to initialize app. Please try refreshing the page.');
    }
});

async function getWebhookToken() {
    if (!currentWebhookUrl) return null;

    try {
        const response = await fetch('/get_webhook_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                webhook_url: currentWebhookUrl
            })
        });

        if (!response.ok) throw new Error('Failed to get webhook token');
        
        const data = await response.json();
        webhookToken = data.token;
        
        // Schedule token refresh
        setTimeout(getWebhookToken, (data.expires_in - 300) * 1000); // Refresh 5 minutes before expiry
        
        return data.token;
    } catch (error) {
        console.error('Error getting webhook token:', error);
        return null;
    }
}

function initializeApp() {
    try {
        loadWebhookUrl();
        // Only refresh if webhook URL exists
        if (webhookUrl) {
            refreshFileList();
        }
    } catch (error) {
        console.error('Initialization error:', error);
        showAlert('Failed to initialize app. Please try refreshing the page.');
    }
}

// Webhook URL Management
async function saveWebhookUrl() {
    const input = document.getElementById('webhook_url');
    const url = input.value.trim();
    
    if (!url) {
        showAlert('Please enter a webhook URL');
        return;
    }

    try {
        // Test webhook URL validity with enhanced embed message and image
        const testEmbed = {
            embeds: [{
                title: "🔒 Channel Access Configuration",
                description: "This Discord channel has been configured as cloud storage for UwU Drive.\n\n" +
                             "⚠️ **Security Warning**\n" +
                             "DO NOT share access to this channel or webhook URL with anyone!\n" +
                             "This channel will be used to store your files securely.\n\n" +
                             "🛡️ **Security Best Practices:**\n" +
                             "• Keep this channel **private**\n" +
                             "• Regularly check **channel permissions**\n" +
                             "• Never share the **webhook URL**\n" +
                             "• Only give access to **trusted administrators**",
                color: 0xff69b4,
                footer: {
                    text: "UwU Drive - Secure Cloud Storage"
                },
                timestamp: new Date().toISOString(),
                image: {
                    url: "attachment://uwu-preview.png"
                }
            }]
        };

        // Create FormData and append the image
        const formData = new FormData();
        formData.append("payload_json", JSON.stringify(testEmbed));
        
        // Fetch and append the image
        const imageResponse = await fetch('/static/img/uwu-preview.png');
        const imageBlob = await imageResponse.blob();
        formData.append('files[0]', imageBlob, 'uwu-preview.png');

        // Test webhook URL with image
        const testResponse = await fetch(url, {
            method: 'POST',
            body: formData
        });

        if (!testResponse.ok) {
            throw new Error('Invalid webhook URL');
        }

        // Clear existing file list and search state before changing webhook
        resetSearchState();
        clearFileList();

        // Store URL both in localStorage and memory
        localStorage.setItem('webhook_url', url);
        currentWebhookUrl = url;
        webhookUrl = url;
        
        // Get new token and refresh list
        await getWebhookToken();
        await refreshFileList(); // Will show all files since search is reset
        
        // Lock the webhook input and update UI
        lockWebhookInput();
        
        showNotification('Webhook URL verified & saved', 'success');

    } catch (e) {
        showNotification('Invalid webhook URL', 'error');
    }
}

// Add new function to handle webhook input locking
function lockWebhookInput() {
    const input = document.getElementById('webhook_url');
    const button = document.getElementById('saveWebhookBtn');
    const lockIcon = document.getElementById('webhookLock');
    
    // Set input and button states
    input.classList.add('locked');
    input.disabled = true;
    button.classList.add('locked');
    button.disabled = true;
    
    // Update lock icon
    lockIcon.classList.remove('fa-lock-open');
    lockIcon.classList.add('fa-lock');
    
    // Update button text
    button.innerHTML = '<i class="fas fa-check"></i> Saved';
    
    // If there's a value, store it
    if (input.value.trim()) {
        webhookUrl = input.value.trim();
        localStorage.setItem('webhook_url', webhookUrl);
    }
}

// Update loadWebhookUrl to include locking
function loadWebhookUrl() {
    const storedWebhookUrl = localStorage.getItem('webhook_url');
    if (storedWebhookUrl) {
        webhookUrl = storedWebhookUrl;
        document.getElementById('webhook_url').value = webhookUrl;
        lockWebhookInput();
        refreshFileList();
    } else {
        lockWebhookInput(); // Lock even if empty
    }
}

// File List Functions
async function refreshFileList() {
    if (!currentWebhookUrl) {
        console.log('No webhook URL found');
        return;
    }

    if (!webhookToken) {
        await getWebhookToken();
    }

    showLoadingState();

    try {
        const response = await fetch('/files', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Webhook-Token': webhookToken
            },
            body: JSON.stringify({
                webhook_url: currentWebhookUrl
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        if (data.files && Array.isArray(data.files)) {
            // Update file list first
            updateFileList(data.files);
            
            // Then reapply search if we're in search mode
            if (window.currentSearchTerm) {
                await searchFiles(null, true); // Pass true to indicate this is a refresh
            }
        }
    } catch (error) {
        console.error('Error fetching files:', error);
        showAlert('Failed to load files: ' + error.message);
    } finally {
        hideLoadingState();
    }
}

function updateFileList(files) {
    const file_list = document.getElementById('file_list');
    const fileCount = document.getElementById('fileCount');
    
    if (!file_list) return;
    
    file_list.innerHTML = '';
    
    if (!Array.isArray(files) || files.length === 0) {
        file_list.innerHTML = '<li class="list-group-item text-center">No files found</li>';
        if (fileCount) fileCount.textContent = '0';
        return;
    }

    files.forEach(file => {
        const li = createFileListItem(file);
        if (li) file_list.appendChild(li);
    });
    
    if (fileCount) fileCount.textContent = files.length;
}

function showLoadingState() {
    const fileList = document.getElementById('file_list');
    if (fileList) {
        fileList.innerHTML = '<li class="list-group-item text-center"><i class="fas fa-spinner fa-spin"></i> Loading...</li>';
    }
}

function hideLoadingState() {
    // Loading state will be cleared by updateFileList
}

function createFileListItem(file) {
    try {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        
        li.innerHTML = `
            <div class="file-info">
                <a href="/file/d/${file.download_id}" target="_blank">
                    <strong>${file.filename}</strong>
                </a> 
                <span class="file-meta">${file.file_size} - ${file.upload_date}</span>
            </div>
            <div class="file-actions">
                <button class="share-heart" onclick="shareLink('${file.download_id}')">
                    <div class="heart-container">
                        <i class="fas fa-heart heart-bg"></i>
                        <i class="fas fa-share-alt share-icon"></i>
                    </div>
                </button>
                <button class="security-btn" onclick="toggleFileAccess('${file.download_id}', '${currentWebhookUrl}')">
                    <div class="security-icon-container">
                        <i class="fas fa-door-${file.is_enabled ? 'open' : 'closed'} access-icon ${file.is_enabled ? 'enabled' : 'disabled'}"></i>
                    </div>
                </button>
                <button class="delete-chocolate" onclick="confirmDelete('${file.filename}', '${file.download_id}')">
                    <div class="chocolate-container">
                        <i class="fas fa-trash-alt trash-icon"></i>
                    </div>
                </button>
            </div>
        `;
        return li;
    } catch (error) {
        console.error('Error creating file list item:', error);
        return null;
    }
}

// Enhanced search function
let searchTimeout;
async function searchFiles(event = null, isRefresh = false) {
    if (event) {
        event.preventDefault();
    }

    const searchInput = document.getElementById('search_input');
    const searchTerm = isRefresh ? window.currentSearchTerm : searchInput.value.trim();
    const file_list = document.getElementById('file_list');
    
    // If search is empty and not a refresh, restore all files
    if (!searchTerm && !isRefresh) {
        const searchLabel = document.querySelector('.recent-files-label');
        searchLabel.innerHTML = '<i class="fas fa-clock"></i> Recent Files';
        window.currentSearchTerm = '';
        isInSearchMode = false;
        lastSearchTerm = '';
        return await refreshFileList();
    }

    if (!webhookUrl || !webhookToken) {
        showNotification('Please configure webhook URL first', 'error');
        return;
    }
    
    try {
        file_list.innerHTML = '<li class="list-group-item text-center"><i class="fas fa-spinner fa-spin"></i> Searching...</li>';

        const response = await fetch('/search_files', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Webhook-Token': webhookToken
            },
            body: JSON.stringify({
                webhook_url: webhookUrl,
                search_term: searchTerm
            })
        });

        if (!response.ok) {
            throw new Error(`Search failed: ${response.status}`);
        }

        const data = await response.json();
        
        // Update search label
        const searchLabel = document.querySelector('.recent-files-label');
        if (searchTerm) {
            searchLabel.innerHTML = `<i class="fas fa-search"></i> Results for "${searchTerm}" (${data.files.length})`;
            window.currentSearchTerm = searchTerm;
            isInSearchMode = true;
            lastSearchTerm = searchTerm;
        }

        // Update file list with search results
        updateFileList(data.files);

    } catch (error) {
        console.error('Search error:', error);
        file_list.innerHTML = '<li class="list-group-item text-center text-danger">Search failed</li>';
        showNotification(error.message, 'error');
    }
}

// Share Link Function
function shareLink(downloadId) {
    if (!downloadId) return;

    const link = `${window.location.origin}/file/d/${downloadId}`;
    const button = event.target.closest('.share-heart');
    if (!button) return;

    const notif = document.createElement('div');
    notif.className = 'copy-notification';
    notif.textContent = 'Copied!';
    button.appendChild(notif);

    navigator.clipboard.writeText(link)
        .then(() => {
            setTimeout(() => {
                notif.remove();
            }, 1500);
        })
        .catch(() => {
            notif.textContent = 'Failed to copy';
            notif.style.backgroundColor = '#ff6b6b';
            setTimeout(() => {
                notif.remove();
            }, 1500);
        });
}

// File Access Toggle
function toggleFileAccess(downloadId, webhookUrl, currentState) {
    if (!downloadId || !webhookUrl) return;

    const button = event.target.closest('.security-btn');
    if (!button) return;

    const icon = button.querySelector('.access-icon');
    button.classList.add('switching');
    
    const formData = new FormData();
    formData.append('download_id', downloadId);
    formData.append('webhook_url', webhookUrl);
    
    fetch('/toggle_file', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const newState = data.is_enabled;
            icon.className = `fas fa-door-${newState ? 'open' : 'closed'} access-icon ${newState ? 'enabled' : 'disabled'}`;
            
            const notif = document.createElement('div');
            notif.className = 'status-notification';
            notif.textContent = newState ? 'Enabled' : 'Disabled';
            button.appendChild(notif);
            
            setTimeout(() => {
                notif.remove();
            }, 1500);
        }
    })
    .finally(() => {
        button.classList.remove('switching');
    });
}

// Make functions globally available
window.refreshFileList = refreshFileList; 
window.shareLink = shareLink;
window.toggleFileAccess = toggleFileAccess;

// Add event listener for popstate to handle browser back/forward
window.addEventListener('popstate', () => {
    const searchParams = new URLSearchParams(window.location.search);
    const searchTerm = searchParams.get('q');
    
    if (searchTerm) {
        isInSearchMode = true;
        lastSearchTerm = searchTerm;
        document.getElementById('search_input').value = searchTerm;
        searchFiles();
    } else {
        isInSearchMode = false;
        lastSearchTerm = '';
        document.getElementById('search_input').value = '';
        document.querySelector('.recent-files-label').innerHTML = '<i class="fas fa-clock"></i> Recent Files';
        refreshFileList();
    }
});

async function uploadFile() {
    try {
        const fileInput = document.getElementById('file_input');
        const file = fileInput.files[0];
        
        if (!file || !webhookUrl) {
            showAlert('Please select a file and set webhook URL');
            return;
        }

        // Generate secure file ID first
        const idResponse = await fetch('/generate_file_id');
        const idData = await idResponse.json();
        const secureId = idData.file_id;

        const formData = new FormData();
        formData.append('file', file);
        formData.append('webhook_url', webhookUrl);
        formData.append('upload_id', secureId);

        const response = await fetch('/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) throw new Error('Upload failed');
        
        const data = await response.json();
        if (data.status === 'success') {
            showAlert('Upload complete! Download link copied to clipboard');
            navigator.clipboard.writeText(`${window.location.origin}/file/d/${data.download_id}`);
            
            // Always refresh the file list first
            await refreshFileList();
            
            // Then reapply search if we're in search mode
            if (window.currentSearchTerm) {
                await searchFiles(null, true);
            }
        } else {
            throw new Error(data.error || 'Upload failed');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showAlert(error.message || 'Upload failed');
    }
}

function toggleWebhookLock() {
    const input = document.getElementById('webhook_url');
    
    if (input.classList.contains('locked')) {
        // Reset search state and clear list before unlocking
        resetSearchState();
        clearFileList();
        unlockWebhookInput();
    }
}

// Add new function to handle webhook URL changes
function clearFileList() {
    const fileList = document.getElementById('file_list');
    const fileCount = document.getElementById('fileCount');
    
    if (fileList) {
        fileList.innerHTML = '<li class="list-group-item text-center">No files found</li>';
    }
    if (fileCount) {
        fileCount.textContent = '0';
    }
}

// Modified unlockWebhookInput function
function unlockWebhookInput() {
    const input = document.getElementById('webhook_url');
    const button = document.getElementById('saveWebhookBtn');
    const lockIcon = document.getElementById('webhookLock');
    
    // Reset webhook states
    input.classList.remove('locked');
    input.disabled = false;
    button.classList.remove('locked');
    button.disabled = false;
    
    lockIcon.classList.remove('fa-lock');
    lockIcon.classList.add('fa-lock-open');
    
    button.innerHTML = '<i class="fas fa-save"></i> Save';
    
    // Clear webhook data
    webhookUrl = null;
    currentWebhookUrl = null;
    webhookToken = null;
    
    // Ensure we're out of search mode
    resetSearchState();
}

// Add new function to reset search state
function resetSearchState() {
    const searchInput = document.getElementById('search_input');
    const searchLabel = document.querySelector('.recent-files-label');
    
    // Reset search input
    if (searchInput) {
        searchInput.value = '';
        searchInput.dispatchEvent(new Event('input')); // Trigger input event
    }
    
    // Reset search label
    if (searchLabel) {
        searchLabel.innerHTML = '<i class="fas fa-clock"></i> Recent Files';
    }
    
    // Reset all search states
    window.currentSearchTerm = '';
    isInSearchMode = false;
    lastSearchTerm = '';
    
    // Reset URL parameters if any
    const url = new URL(window.location);
    if (url.searchParams.has('q')) {
        url.searchParams.delete('q');
        window.history.replaceState({}, '', url);
    }
}

// Add notification function
function showNotification(message, type = 'success') {
    // Remove any existing notifications first
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notif => notif.remove());

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    document.body.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);

    // Remove after animation
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
