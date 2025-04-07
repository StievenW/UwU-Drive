// Konstanta untuk manajemen file
const CHUNK_SIZE = 8 * 1024 * 1024; // 8MB chunks

class ChunkTracker {
    constructor() {
        this.chunks = {};
        this.totalChunks = 0;
        this.processedChunks = 0;
    }

    addChunk(chunkNumber, data) {
        this.chunks[chunkNumber] = data;
        this.processedChunks++;
    }

    isComplete() {
        return this.processedChunks === this.totalChunks;
    }

    reset() {
        this.chunks = {};
        this.processedChunks = 0;
    }
}

// Add search state management
let currentSearchTerm = '';

function shortenFileName(filename, maxLength = 30) {
    if (filename.length <= maxLength) return filename;
    const extension = filename.split('.').pop();
    const nameWithoutExt = filename.slice(0, -(extension.length + 1));
    const shortName = nameWithoutExt.slice(0, maxLength - 3 - extension.length) + '...';
    return `${shortName}.${extension}`;
}

function createFileListItem(file) {
    const li = document.createElement('li');
    li.className = 'list-group-item';
    li.dataset.fileId = file.download_id;
    li.dataset.filename = file.filename;
    
    // Add search term check and visibility control
    const fileNameLower = file.filename.toLowerCase();
    const isVisible = !currentSearchTerm || fileNameLower.includes(currentSearchTerm.toLowerCase());
    li.style.display = isVisible ? 'flex' : 'none';
    li.dataset.searchMatch = isVisible.toString();
    
    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';

    const shortenedName = shortenFileName(file.filename);
    const needsTooltip = shortenedName !== file.filename;
    
    fileInfo.innerHTML = `
        <a href="/file/d/${file.download_id}" target="_blank" ${needsTooltip ? `title="${file.filename}"` : ''}>
            <strong>${shortenedName}</strong>
        </a>
        <span class="file-meta">${file.file_size} - ${file.upload_date}</span>
    `;

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'file-actions';

    actionsDiv.innerHTML = `
        <button class="share-heart" onclick="shareLink('${file.download_id}')" title="Share file">
            <div class="heart-container">
                <i class="fas fa-heart heart-bg"></i>
                <i class="fas fa-share-alt share-icon"></i>
            </div>
        </button>
        <button class="security-btn" onclick="togglePassword('${file.download_id}', '${file.filename}')" title="Set password">
            <div class="security-icon-container">
                <i class="fas fa-key access-icon ${file.has_password ? 'enabled' : 'disabled'}"></i>
            </div>
        </button>
        <button class="security-btn" onclick="toggleFileAccess('${file.download_id}', '${localStorage.getItem('webhook_url')}')" title="Toggle access">
            <div class="security-icon-container">
                <i class="fas fa-door-${file.is_enabled ? 'open' : 'closed'} access-icon ${file.is_enabled ? 'enabled' : 'disabled'}"></i>
            </div>
        </button>
        <button class="delete-chocolate" onclick="deleteFile('${file.download_id}', '${file.filename}')" title="Delete file">
            <div class="chocolate-container">
                <i class="fas fa-trash-alt trash-icon"></i>
            </div>
        </button>
    `;

    li.appendChild(fileInfo);
    li.appendChild(actionsDiv);
    
    return li;
}

// Add file action functions
let currentFileId = null;
let currentFileName = null;

function togglePassword(fileId, filename) {
    // Check if file matches current search term
    const item = document.querySelector(`li[data-file-id="${fileId}"]`);
    if (item && item.dataset.searchMatch === 'false') {
        return;
    }
    
    currentFileId = fileId;
    currentFileName = filename;
    
    // Get modal elements
    const passwordModal = document.getElementById('passwordModal');
    const passwordInput = document.getElementById('filePassword');
    
    // Clear previous values
    passwordInput.value = '';
    document.getElementById('passwordAlert').style.display = 'none';
    
    // Initialize modal with Bootstrap 5
    const modal = new bootstrap.Modal(passwordModal);
    modal.show();
    
    // Focus input after modal is shown
    passwordModal.addEventListener('shown.bs.modal', function () {
        passwordInput.focus();
    });

    // Handle Enter key
    passwordInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            setFilePassword();
        }
    });
}

async function setFilePassword() {
    const passwordInput = document.getElementById('filePassword');
    const alert = document.getElementById('passwordAlert');
    const passwordModal = document.getElementById('passwordModal');
    
    try {
        const formData = new FormData();
        formData.append('download_id', currentFileId);
        formData.append('webhook_url', localStorage.getItem('webhook_url'));
        formData.append('password', passwordInput.value);

        const response = await fetch('/set_password', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        if (response.ok) {
            // Hide modal first
            const modal = bootstrap.Modal.getInstance(passwordModal);
            modal.hide();
            
            // Handle refresh and search before showing notification
            await refreshFileList();
            if (currentSearchTerm) {
                updateSearchResults(currentSearchTerm);
            }
            
            // Show notification last
            showNotification('Password updated successfully', 'success');
        } else {
            alert.textContent = data.error || 'Failed to set password';
            alert.style.display = 'block';
        }
    } catch (error) {
        console.error('Set password error:', error);
        alert.textContent = 'Error setting password';
        alert.style.display = 'block';
    }
}

function deleteFile(fileId, filename) {
    // Check if file matches current search term
    const item = document.querySelector(`li[data-file-id="${fileId}"]`);
    if (item && item.dataset.searchMatch === 'false') {
        return;
    }
    
    currentFileId = fileId;
    currentFileName = filename;
    
    // Get modal elements
    const deleteModal = document.getElementById('deleteModal');
    const fileNameElement = document.getElementById('deleteFileName');
    
    // Set filename in modal
    fileNameElement.textContent = filename;
    
    // Initialize and show modal
    const modal = new bootstrap.Modal(deleteModal);
    modal.show();
}

async function confirmDeleteFile() {
    const deleteModal = document.getElementById('deleteModal');
    
    try {
        const formData = new FormData();
        formData.append('download_id', currentFileId);
        formData.append('webhook_url', localStorage.getItem('webhook_url'));
        formData.append('filename', currentFileName);

        const response = await fetch('/delete', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(await response.text());
        }

        // Hide modal first
        const modal = bootstrap.Modal.getInstance(deleteModal);
        modal.hide();

        // Remove file item with animation
        const item = document.querySelector(`li[data-file-id="${currentFileId}"]`);
        if (item) {
            item.style.animation = 'slideOut 0.3s ease';
            setTimeout(async () => {
                item.remove();
                // Handle refresh and search before showing notification
                await refreshFileList();
                if (currentSearchTerm) {
                    updateSearchResults(currentSearchTerm);
                }
                
                // Show notification last
                showNotification('File deleted successfully', 'success');
            }, 300);
        }
        
    } catch (error) {
        console.error('Delete error:', error);
        showNotification(error.message || 'Failed to delete file', 'error');
    }
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `fade-notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 3000);
}

// Update search update function to handle count update
function updateSearchResults(searchTerm) {
    currentSearchTerm = searchTerm.toLowerCase();
    const fileItems = document.querySelectorAll('.list-group-item');
    let visibleCount = 0;
    
    fileItems.forEach(item => {
        const filename = item.dataset.filename.toLowerCase();
        const isVisible = !currentSearchTerm || filename.includes(currentSearchTerm);
        item.style.display = isVisible ? 'flex' : 'none';
        item.dataset.searchMatch = isVisible.toString();
        if (isVisible) visibleCount++;
    });

    // Update search label count if exists
    const searchLabel = document.querySelector('.recent-files-label');
    if (searchLabel && currentSearchTerm) {
        searchLabel.innerHTML = `<i class="fas fa-search"></i> Results for "${currentSearchTerm}" (${visibleCount})`;
    }
}

// Make functions globally available
window.createFileListItem = createFileListItem;
window.togglePassword = togglePassword;
window.setFilePassword = setFilePassword;
window.deleteFile = deleteFile;
window.confirmDeleteFile = confirmDeleteFile;
window.updateSearchResults = updateSearchResults;
