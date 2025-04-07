let uploadInProgress = false;
let currentUploadId = null;
let shouldCancelUpload = false;

const MAX_CHUNK_SIZE = 9.99 * 1024 * 1024; // 9.9MB in bytes
const MAX_RETRIES = 3;
const CONCURRENT_UPLOADS = 3;
const CHUNK_DELAY = 500;
const RETRY_DELAY = 2000;

// Simplified file upload function
async function uploadFile() {
    const startTime = Date.now(); // Add this line to track start time
    const fileInput = document.getElementById('file_input');
    const file = fileInput.files[0];
    const webhookUrl = localStorage.getItem('webhook_url');
    
    if (!file || !webhookUrl) {
        showAlert('Please select a file and set webhook URL');
        return;
    }

    // Enhanced status box
    const statusBox = document.createElement('div');
    statusBox.className = 'upload-progress-box active';
    statusBox.innerHTML = `
        <div class="upload-header">
            <span class="title">Uploading File</span>
            <div class="controls">
                <span class="toggle-btn">▼</span>
                <span class="close-btn">×</span>
            </div>
        </div>
        <div class="upload-details">
            <div class="filename">${file.name}</div>
            <div class="status-text">Preparing upload...</div>
            <div class="upload-stats">
                <span class="chunk-status">Chunk: 0 / 0</span>
                <span class="size-status">Size: 0 B / ${formatFileSize(file.size)}</span>
            </div>
        </div>
    `;
    document.body.appendChild(statusBox);

    // Add event listeners for controls
    const toggleBtn = statusBox.querySelector('.toggle-btn');
    const closeBtn = statusBox.querySelector('.close-btn');
    const details = statusBox.querySelector('.upload-details');

    toggleBtn.addEventListener('click', () => {
        details.classList.toggle('hidden');
        toggleBtn.textContent = details.classList.contains('hidden') ? '▲' : '▼';
    });

    closeBtn.addEventListener('click', () => {
        shouldCancelUpload = true;
        statusBox.remove();
    });

    try {
        uploadInProgress = true;
        shouldCancelUpload = false;
        currentUploadId = Date.now().toString();
        toggleUploadFormLock(true);
        toggleRetroTransfer(true); // Show animation when upload starts

        const totalFileSize = file.size;
        const chunks = splitFileIntoChunks(file);
        const totalChunks = chunks.length;
        const successfulChunks = [];
        let uploadedChunks = 0;
        let uploadedSize = 0;

        // Sequential upload with enhanced progress
        for (let sequence = 0; sequence < totalChunks; sequence++) {
            if (shouldCancelUpload) {
                // Ubah error handling menjadi notifikasi sederhana
                const notification = document.createElement('div');
                notification.className = 'fade-notification';
                notification.textContent = 'Upload cancelled';
                document.body.appendChild(notification);
                
                setTimeout(() => notification.remove(), 3000);
                return; // Langsung return tanpa throw error
            }

            let result = null;
            for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
                try {
                    const formData = new FormData();
                    formData.append('file', chunks[sequence].blob, file.name);
                    formData.append('webhook_url', webhookUrl);
                    formData.append('upload_id', currentUploadId);
                    formData.append('part_number', sequence);
                    formData.append('total_parts', totalChunks);
                    formData.append('filename', file.name);
                    formData.append('chunk_size', chunks[sequence].blob.size);

                    result = await uploadChunk(chunks[sequence], formData);

                    uploadedChunks++;
                    uploadedSize += chunks[sequence].blob.size;
                    const progress = Math.round((uploadedSize / totalFileSize) * 100);
                    const statusText = statusBox.querySelector('.status-text');
                    const chunkStatus = statusBox.querySelector('.chunk-status');
                    const sizeStatus = statusBox.querySelector('.size-status');

                    statusText.textContent = `Uploading... ${progress}%`;
                    chunkStatus.textContent = `Chunk: ${sequence + 1} / ${totalChunks}`;
                    sizeStatus.textContent = `Size: ${formatFileSize(uploadedSize)} / ${formatFileSize(totalFileSize)}`;

                    break;
                } catch (error) {
                    if (attempt === MAX_RETRIES - 1) throw error;
                    await delay(RETRY_DELAY * Math.pow(2, attempt));
                }
            }

            if (!result || !result.success) {
                throw new Error(`Failed to upload chunk ${sequence + 1}`);
            }

            successfulChunks.push({
                chunk_number: sequence,
                file_url: result.file_url,
                chunk_size: chunks[sequence].blob.size,
                original_name: `${file.name}.part${sequence}`
            });

            await delay(CHUNK_DELAY);
        }

        statusBox.querySelector('.status-text').textContent = 'Finalizing upload...';

        const completeResponse = await fetch('/complete_upload', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                upload_id: currentUploadId,
                filename: file.name,
                webhook_url: webhookUrl,
                total_size: totalFileSize,
                mime_type: file.type,
                chunks: successfulChunks
            })
        });

        if (!completeResponse.ok) throw new Error('Failed to complete upload');

        const completionData = await completeResponse.json();
        
        if (completionData.success) {
            // Send final success embed
            try {
                const processingTime = ((Date.now() - startTime) / 1000).toFixed(2);
                
                const finalEmbed = {
                    embeds: [{
                        title: "✅ File Upload Complete",
                        color: 0x00ff00,
                        description: `File has been successfully uploaded and is ready for download.`,
                        fields: [
                            {
                                name: "📝 File Details",
                                value: [
                                    `**Name:** \`${file.name}\``,
                                    `**Size:** ${formatFileSize(totalFileSize)}`,
                                    `**Type:** ${file.type || 'Unknown'}`
                                ].join('\n'),
                                inline: false
                            },
                            {
                                name: "📊 Upload Statistics",
                                value: [
                                    `**Total Chunks:** ${totalChunks}`,
                                    `**Processing Time:** ${processingTime} seconds`
                                ].join('\n'),
                                inline: true
                            },
                            {
                                name: "🔗 Access Information",
                                value: [
                                    `**Download Link:** ${completionData.download_link}`,
                                    `**Upload Date:** ${new Date().toLocaleString()}`,
                                    `**Download ID:** \`${completionData.download_id}\``
                                ].join('\n'),
                                inline: true
                            }
                        ],
                        footer: {
                            text: "UwU Drive • Secure File Storage System"
                        },
                        timestamp: new Date().toISOString()
                    }]
                };

                // Send final embed
                const embedResponse = await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(finalEmbed)
                });

                if (!embedResponse.ok) {
                    console.error('Failed to send completion embed:', await embedResponse.text());
                }
            } catch (embedError) {
                console.error('Error sending completion embed:', embedError);
            }

            // Show simple fade notification
            const notification = document.createElement('div');
            notification.className = 'fade-notification success';
            notification.textContent = 'Upload complete!';
            document.body.appendChild(notification);
            
            // Remove notification after animation
            setTimeout(() => {
                notification.remove();
            }, 3000);

            await refreshFileList();
        } else {
            throw new Error(completionData.error || 'Failed to complete upload');
        }

    } catch (error) {
        console.error('Upload error:', error);
        // Tampilkan error sebagai notifikasi memudar
        const notification = document.createElement('div');
        notification.className = 'fade-notification error';
        notification.textContent = error.message;
        document.body.appendChild(notification);
        
        setTimeout(() => notification.remove(), 3000);
    } finally {
        toggleRetroTransfer(false); // Hide animation when upload ends
        if (!shouldCancelUpload) {
            setTimeout(() => statusBox.remove(), 3000);
        }
        resetUploadState();
    }
}

// Utility functions
function toggleUploadFormLock(lock) {
    const uploadForm = document.getElementById('upload_form');
    const fileInput = document.getElementById('file_input');
    if (lock) {
        uploadForm.classList.add('upload-locked');
        fileInput.disabled = true;
    } else {
        uploadForm.classList.remove('upload-locked');
        fileInput.disabled = false;
    }
}

function resetUploadState() {
    uploadInProgress = false;
    currentUploadId = null;
    shouldCancelUpload = false;
    toggleUploadFormLock(false);
    document.getElementById('file_input').value = '';
    document.getElementById('filePreview').classList.add('hidden');
}

function splitFileIntoChunks(file) {
    const chunks = [];
    let start = 0;
    
    while (start < file.size) {
        const end = Math.min(start + MAX_CHUNK_SIZE, file.size);
        chunks.push({
            blob: file.slice(start, end),
            start: start,
            end: end
        });
        start = end;
    }
    
    return chunks;
}

// Add file preview function
function previewFile(file) {
    const preview = document.getElementById('filePreview');
    const content = document.getElementById('previewContent');
    
    if (!file) {
        preview.classList.add('hidden');
        return;
    }

    // Format file size
    const size = formatFileSize(file.size);
    
    // Get icon based on mime type
    const iconClass = getMimeTypeIcon(file.type);
    
    // Create preview content with mime type info
    content.innerHTML = `
        <div class="preview-item">
            <i class="${iconClass}"></i>
            <div class="preview-details">
                <div class="preview-filename">${file.name}</div>
                <div class="preview-meta">
                    ${size} • ${file.type || 'Unknown type'}
                </div>
            </div>
        </div>
    `;

    // Show preview
    preview.classList.remove('hidden');
}

// Add helper function to get appropriate icon
function getMimeTypeIcon(mimeType) {
    if (!mimeType) return 'fas fa-file';
    
    if (mimeType.startsWith('image/')) return 'fas fa-file-image';
    if (mimeType.startsWith('video/')) return 'fas fa-file-video';
    if (mimeType.startsWith('audio/')) return 'fas fa-file-audio';
    if (mimeType.startsWith('text/')) return 'fas fa-file-alt';
    if (mimeType.includes('pdf')) return 'fas fa-file-pdf';
    if (mimeType.includes('word') || mimeType.includes('document')) return 'fas fa-file-word';
    if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) return 'fas fa-file-excel';
    if (mimeType.includes('zip') || mimeType.includes('compressed')) return 'fas fa-file-archive';
    
    return 'fas fa-file';
}

// Add helper function for file size formatting
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add delay utility function
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showAlert(message, type = 'info') {
    const alertModal = document.getElementById('alertModal');
    const alertBody = document.getElementById('alertModalBody');
    if (alertModal && alertBody) {
        alertBody.textContent = message;
        $('#alertModal').modal('show');
    } else {
        alert(message);
    }
}

function toggleRetroTransfer(show) {
    const retroTransfer = document.querySelector('.retro-transfer');
    if (show) {
        retroTransfer.classList.add('active');
        document.querySelector('.uploader-content').classList.add('uploading');
    } else {
        retroTransfer.classList.remove('active');
        document.querySelector('.uploader-content').classList.remove('uploading');
    }
}

// Update event listeners
document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('upload_form');
    const fileInput = document.getElementById('file_input');
    const uploadButton = document.getElementById('uploadButton');

    // File input change handler
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            previewFile(file);
            uploadButton.disabled = false;
        } else {
            previewFile(null);
            uploadButton.disabled = true;
        }
    });

    // Upload button click handler
    uploadButton.addEventListener('click', () => {
        if (!uploadInProgress) {
            uploadFile();
        }
    });

    // Drag and drop handlers
    uploadForm.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadForm.classList.add('drag-over');
    });

    uploadForm.addEventListener('dragleave', (e) => {
        e.preventDefault();
        uploadForm.classList.remove('drag-over');
    });

    uploadForm.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadForm.classList.remove('drag-over');
        
        const file = e.dataTransfer.files[0];
        if (file) {
            fileInput.files = e.dataTransfer.files;
            previewFile(file);
            uploadButton.disabled = false;
        }
    });
});

async function uploadChunk(chunk, formData) {
    try {
        const file = formData.get('file');
        formData.append('mime_type', file.type || 'application/octet-stream');
        
        // Get current webhook URL from memory
        const currentWebhookUrl = localStorage.getItem('webhook_url');
        if (!currentWebhookUrl) {
            throw new Error('Webhook URL not configured');
        }

        // Send embed first
        const embed = {
            embeds: [{
                title: "📤 File Upload Progress",
                color: 0xff69b4,
                description: "Uploading file chunk to storage",
                fields: [
                    {
                        name: "📝 File Information",
                        value: `Filename: \`${formData.get('filename')}\`\nType: ${file.type || 'Unknown'}\nPart ${parseInt(formData.get('part_number'))+1} of ${formData.get('total_parts')}`,
                        inline: false
                    },
                    {
                        name: "📦 Chunk Details",
                        value: `Size: ${formatFileSize(formData.get('chunk_size'))}`,
                        inline: true
                    },
                    {
                        name: "🔒 Security",
                        value: "Secured chunk transfer",
                        inline: true
                    }
                ],
                footer: {
                    text: "UwU Drive • Secure File Storage System"
                },
                timestamp: new Date().toISOString()
            }]
        };

        await fetch(currentWebhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(embed)
        });

        // Use current webhook URL for upload
        formData.set('webhook_url', currentWebhookUrl);

        const response = await fetch('/upload_chunk', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Chunk upload failed: ${response.status}`);
        }

        return response.json();
    } catch (error) {
        console.error('Upload chunk error:', error);
        throw error;
    }
}
