let downloadId;
let fileDetails = null;
let isDownloading = false;
let chunks = [];
let downloadToken = null;
let shouldCancelDownload = false;
let allowClose = false;

document.addEventListener('DOMContentLoaded', () => {
    // Get download ID from URL
    const pathParts = window.location.pathname.split('/');
    downloadId = pathParts[pathParts.length - 1];
    
    // Load file details
    loadFileDetails();
});

window.addEventListener('beforeunload', function(e) {
    if (isDownloading) {
        e.preventDefault();
        e.returnValue = '';
        return '';
    }
});

async function loadFileDetails() {
    try {
        const response = await fetch(`/file/details/${downloadId}`);
        fileDetails = await response.json();

        if (response.ok) {
            downloadToken = fileDetails.download_token;
            updateUI(fileDetails);
        } else {
            showError('File not found or access denied');
        }
    } catch (error) {
        console.error('Error loading file details:', error);
        showError('Failed to load file details');
    }
}

async function getChunkInfo() {
    const response = await fetch(`/file/chunks/${downloadId}`, {
        headers: {
            'X-Download-Token': downloadToken
        }
    });
    if (!response.ok) throw new Error('Failed to get chunk info');
    return response.json();
}

async function downloadChunk(chunkInfo) {
    const response = await fetch(`/proxy_chunk/${downloadId}/${chunkInfo.part}`, {
        headers: {
            'X-Download-Token': downloadToken,
            'X-Chunk-Signature': chunkInfo.signature
        }
    });
    if (!response.ok) throw new Error('Chunk download failed');
    return response.arrayBuffer();
}

function updateUI(details) {
    document.getElementById('filename').textContent = details.filename;
    document.getElementById('pageTitle').textContent = `${details.filename} - UwU Drive`;
    document.getElementById('fileSize').textContent = details.file_size;
    document.getElementById('uploadDate').textContent = details.upload_date;
    document.getElementById('fileType').textContent = details.mime_type || 'Unknown type';
    
    // Update file icon based on mime type
    const fileIcon = document.querySelector('.file-icon i');
    fileIcon.className = getMimeTypeIcon(details.mime_type);

    const downloadSection = document.getElementById('downloadSection');
    const passwordSection = document.getElementById('passwordSection');
    const disabledNotice = document.getElementById('disabledNotice');
    const previewSection = document.getElementById('previewSection');
    let previewBtn = document.getElementById('previewBtn');

    // Reset visibility
    downloadSection.style.display = 'none';
    passwordSection.style.display = 'none';
    disabledNotice.style.display = 'none';
    previewSection.style.display = 'none';

    // Handle disabled files
    if (!details.is_enabled) {
        disabledNotice.style.display = 'block';
        return;
    }

    // Handle password protected files
    if (details.has_password) {
        if (!details.is_verified) {
            passwordSection.style.display = 'block';
        } else {
            downloadSection.style.display = 'block';
            if (canPreviewFile(details)) {
                previewSection.style.display = 'block';
                if (!previewBtn) {
                    previewBtn = document.createElement('button');
                    previewBtn.className = 'preview-btn';
                    previewBtn.id = 'previewBtn';
                    previewBtn.onclick = togglePreview;
                    previewSection.appendChild(previewBtn);
                }
                if (details.total_parts > 4) {
                    previewBtn.disabled = true;
                    previewBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Preview not available';
                } else {
                    previewBtn.disabled = false;
                    previewBtn.innerHTML = '<i class="fas fa-eye"></i> Preview';
                }
            }
        }
    } else {
        downloadSection.style.display = 'block';
        if (canPreviewFile(details)) {
            previewSection.style.display = 'block';
            if (!previewBtn) {
                previewBtn = document.createElement('button');
                previewBtn.className = 'preview-btn';
                previewBtn.id = 'previewBtn';
                previewBtn.onclick = togglePreview;
                previewSection.appendChild(previewBtn);
            }
            if (details.total_parts > 4) {
                previewBtn.disabled = true;
                previewBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Preview not available';
            } else {
                previewBtn.disabled = false;
                previewBtn.innerHTML = '<i class="fas fa-eye"></i> Preview';
            }
        }
    }
}

// Add same helper function as upload.js
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

function showPasswordModal() {
    // Reset password input and alert
    document.getElementById('passwordInput').value = '';
    document.getElementById('passwordAlert').style.display = 'none';
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('passwordModal'));
    modal.show();
    
    // Focus password input
    document.getElementById('passwordInput').focus();
}

async function verifyPassword() {
    const password = document.getElementById('passwordInput').value;
    const alert = document.getElementById('passwordAlert');
    const modal = bootstrap.Modal.getInstance(document.getElementById('passwordModal'));

    try {
        const response = await fetch('/verify_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                download_id: downloadId,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok && data.verified) {
            // Get fresh token and details after password verification
            const detailsResponse = await fetch(`/file/details/${downloadId}`);
            const details = await detailsResponse.json();
            
            if (detailsResponse.ok) {
                downloadToken = details.download_token;
                modal.hide();
                
                // Update UI with new verified state
                details.is_verified = true;
                updateUI(details);
            } else {
                throw new Error('Failed to refresh download token');
            }
        } else {
            alert.textContent = data.code === 'FILE_DISABLED' ? 
                'This file has been disabled by the owner.' : 
                'Incorrect password, please try again.';
            alert.style.display = 'block';
        }
    } catch (error) {
        console.error('Password verification error:', error);
        alert.textContent = 'Error verifying password. Please try again.';
        alert.style.display = 'block';
    }
}

async function startDownload() {
    if (isDownloading) return;
    
    if (!downloadToken) {
        showError('Invalid download session');
        return;
    }

    isDownloading = true;
    shouldCancelDownload = false;
    const downloadBtn = document.getElementById('downloadBtn');
    const progressWrapper = document.getElementById('progressWrapper');
    const progressBar = document.getElementById('downloadProgress');
    const progressText = progressBar.querySelector('.progress-text');
    const currentChunkSpan = document.getElementById('currentChunk');
    const totalChunksSpan = document.getElementById('totalChunks');
    const downloadedSizeSpan = document.getElementById('downloadedSize');
    const totalSizeSpan = document.getElementById('totalSize');
    const downloadSpeedSpan = document.getElementById('downloadSpeed');
    
    try {
        allowClose = false; // Reset allowClose flag when starting download
        downloadBtn.disabled = true;
        progressWrapper.style.display = 'block';
        progressWrapper.classList.remove('collapsed'); // Ensure expanded on start
        document.getElementById('toggleBtn').textContent = '▼'; // Reset toggle button

        const info = await getChunkInfo();
        if (!info.success) {
            throw new Error(info.error || 'Failed to get chunk info');
        }

        const chunks = [];
        let downloadedSize = 0;
        let lastTime = Date.now();
        let lastDownloadedSize = 0;

        // Initialize display
        totalChunksSpan.textContent = info.total_parts;
        totalSizeSpan.textContent = formatSize(info.total_size);

        // Download chunks sequentially
        for (let i = 0; i < info.chunks.length; i++) {
            if (shouldCancelDownload) {
                showFadingNotification('Download cancelled by user', 'error');
                throw new Error('Download cancelled by user');
            }

            try {
                const chunk = info.chunks[i];
                const startTime = Date.now();
                const response = await fetch(`/proxy_chunk/${downloadId}/${chunk.part}`, {
                    headers: {
                        'X-Download-Token': downloadToken,
                        'X-Chunk-Signature': chunk.signature
                    }
                });

                if (!response.ok) throw new Error(`Chunk download failed: ${response.statusText}`);
                
                const data = await response.arrayBuffer();
                downloadedSize += data.byteLength;
                chunks.push(data);

                // Update progress
                currentChunkSpan.textContent = i + 1;
                downloadedSizeSpan.textContent = formatSize(downloadedSize);
                const progress = (downloadedSize / info.total_size) * 100;
                progressBar.style.width = `${progress}%`;
                progressText.textContent = `${Math.round(progress)}%`;

                // Calculate and display download speed
                const currentTime = Date.now();
                const timeDiff = (currentTime - lastTime) / 1000; // in seconds
                const sizeDiff = downloadedSize - lastDownloadedSize; // in bytes
                const speed = sizeDiff / timeDiff; // in bytes per second
                downloadSpeedSpan.textContent = `${formatSize(speed)}/s`;
                lastTime = currentTime;
                lastDownloadedSize = downloadedSize;

            } catch (chunkError) {
                console.error(`Error downloading chunk ${i}:`, chunkError);
                throw new Error(`Failed to download chunk ${i + 1}/${info.total_parts}`);
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        // Create complete file and trigger download
        const blob = new Blob(chunks, { type: fileDetails.mime_type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = fileDetails.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        // Cleanup
        chunks.length = 0;
        URL.revokeObjectURL(url);
        
        // Update UI final
        progressBar.style.width = '100%';
        progressText.textContent = '100%';
        progressBar.classList.remove('progress-bar-animated');
        downloadBtn.innerHTML = '<i class="fas fa-check"></i> Download Complete';
        
    } catch (error) {
        console.error('Download error:', error);
        showFadingNotification(`Download failed: ${error.message}`, 'error');
        progressBar.classList.add('bg-danger');
    } finally {
        isDownloading = false;
        downloadBtn.disabled = false;
        allowClose = true; // Allow closing after download completes or fails
    }
}

function showError(message) {
    const container = document.querySelector('.download-container');
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger mt-3';
    alert.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
    container.appendChild(alert);
}

function formatSize(bytes) {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    // Add toFixed(2) for 2 decimal places
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
}

function hideProgressBox() {
    const progressWrapper = document.getElementById('progressWrapper');
    progressWrapper.style.display = 'none';
    progressWrapper.classList.remove('collapsed'); // Reset collapsed state
    document.getElementById('toggleBtn').textContent = '▼'; // Reset toggle button
}

function cancelDownload() {
    shouldCancelDownload = true;
    hideProgressBox();
}

function showFadingNotification(message, type = 'error') {
    const notification = document.createElement('div');
    notification.className = `fade-notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);

    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

function toggleProgressDetails() {
    const details = document.getElementById('progressDetails');
    details.style.display = details.style.display === 'none' ? 'block' : 'none';
}

function toggleProgressBox() {
    const wrapper = document.getElementById('progressWrapper');
    const toggleBtn = document.getElementById('toggleBtn');
    wrapper.classList.toggle('collapsed');
}

// Add event listener for page load/refresh
window.addEventListener('load', () => {
    // Clear any existing verification state
    if (downloadId) {
        loadFileDetails();
    }
});

function canPreviewFile(details) {
    const mimeType = details.mime_type || '';
    return mimeType.startsWith('image/') ||
           mimeType.startsWith('video/') ||
           mimeType.startsWith('audio/') ||
           mimeType === 'application/pdf';
}

function getProxyHeaders(signature) {
    if (!downloadToken || !signature) {
        throw new Error('Invalid token or signature');
    }
    return {
        'X-Download-Token': downloadToken,
        'X-Chunk-Signature': signature,
        'Accept': '*/*',
        'Cache-Control': 'no-cache'
    };
}

function closePreviewModal() {
    const modal = document.getElementById('previewModal');
    modal.style.display = 'none';
    cleanupPreview();
    
    // Change the button text back to "Preview"
    const previewBtn = document.getElementById('previewBtn');
    previewBtn.innerHTML = '<i class="fas fa-eye"></i> Preview';
}

async function togglePreview() {
    const container = document.getElementById('previewContainer');
    const previewBtn = document.getElementById('previewBtn');
    const modal = document.getElementById('previewModal');

    if (previewBtn.disabled) {
        return; // Prevent loading preview if button is disabled
    }

    if (modal.style.display === 'flex') {
        closePreviewModal();
        return;
    }

    // Add loading state
    previewBtn.classList.add('loading');
    
    try {
        const info = await getChunkInfo();
        if (!info.success || info.total_parts > 4) {
            previewBtn.disabled = true;
            previewBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Preview not available';
            throw new Error('Preview only available for files with up to 4 chunks');
        }

        const previewUrl = `/preview/${downloadId}`;
        const mimeType = fileDetails.mime_type;
        const headers = getProxyHeaders(info.chunks[0].signature);

        cleanupPreview();
        
        let previewElement;
        if (mimeType.startsWith('image/')) {
            previewElement = await createImagePreview(previewUrl, headers);
        } 
        else if (mimeType.startsWith('video/')) {
            previewElement = await createVideoPreview(previewUrl, headers);
        } 
        else if (mimeType.startsWith('audio/')) {
            previewElement = await createAudioPreview(previewUrl, headers);
        } 
        else if (mimeType === 'application/pdf') {
            previewElement = await createPDFPreview(previewUrl, headers);
        }
        else {
            throw new Error('Unsupported file type for preview');
        }

        container.appendChild(previewElement);
        modal.style.display = 'flex';
        previewBtn.innerHTML = '<i class="fas fa-eye-slash"></i> Hide Preview';

    } catch (error) {
        console.error('Preview error:', error);
        showFadingNotification(error.message, 'error');
    } finally {
        // Remove loading state
        previewBtn.classList.remove('loading');
        if (!previewBtn.disabled) {
            previewBtn.innerHTML = '<i class="fas fa-eye"></i> Preview';
        }
    }
}

function createImagePreview(url, headers) {
    return new Promise((resolve, reject) => {
        const imageContainer = document.createElement('div');
        imageContainer.className = 'image-preview-container';
        
        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.className = 'preview-close-btn';
        closeBtn.innerHTML = '<i class="fas fa-times"></i>';
        closeBtn.onclick = closePreviewModal;
        imageContainer.appendChild(closeBtn);
        
        // Single loader
        const loader = document.createElement('div');
        loader.className = 'preview-loader';
        loader.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        imageContainer.appendChild(loader);

        // Single image
        const img = new Image();
        img.className = 'preview-image';
        img.alt = fileDetails.filename;

        fetch(url.replace('/preview/', '/preview/image/'), {
            method: 'GET',
            headers: headers,
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data.url) {
                throw new Error('Invalid preview response');
            }

            // Set image load handlers
            img.onload = () => {
                loader.remove();
                img.dataset.lightbox = 'preview';
                img.dataset.title = fileDetails.filename;
                imageContainer.appendChild(img);
                resolve(imageContainer);
            };
            
            img.onerror = (e) => {
                console.error('Image load error:', e);
                reject(new Error('Failed to load image'));
            };

            // Load image from secure URL
            img.crossOrigin = 'anonymous'; // Add this line
            img.src = data.url;

            // Auto cleanup after expiry
            setTimeout(() => {
                if (img.parentElement) {
                    img.src = '';
                    img.remove();
                }
            }, (data.expires_in * 1000) - 1000);
        })
        .catch(error => {
            loader.remove();
            console.error('Image preview error:', error);
            reject(error);
        });
    });
}

function createVideoPreview(url, headers) {
    return new Promise((resolve, reject) => {
        const videoContainer = document.createElement('div');
        videoContainer.className = 'video-player';

        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.className = 'preview-close-btn';
        closeBtn.innerHTML = '<i class="fas fa-times"></i>';
        closeBtn.onclick = closePreviewModal;
        videoContainer.appendChild(closeBtn);

        fetch(url.replace('/preview/', '/preview/video/'), {
            headers: headers
        })
        .then(response => response.json())
        .then(data => {
            if (!data.url || !data.token) {
                throw new Error('Invalid preview response');
            }

            const video = document.createElement('video');
            video.className = 'video-js vjs-theme-fantasy vjs-big-play-centered';
            video.controls = true;
            videoContainer.appendChild(video);

            const player = videojs(video, {
                controls: true,
                autoplay: false,
                preload: 'auto',
                responsive: true,
                fluid: false,
                playbackRates: [0.5, 1, 1.5, 2],
                controlBar: {
                    children: [
                        'playToggle',
                        'volumePanel',
                        'currentTimeDisplay',
                        'timeDivider',
                        'durationDisplay',
                        'progressControl',
                        'playbackRateMenuButton',
                        'fullscreenToggle'
                    ]
                }
            });

            player.src({
                src: data.url,
                type: 'video/mp4'
            });

            // Handle video metadata to detect orientation
            player.on('loadedmetadata', () => {
                const videoElement = player.el().querySelector('video');
                const videoWidth = videoElement.videoWidth;
                const videoHeight = videoElement.videoHeight;
                
                // Set orientation class
                if (videoHeight > videoWidth) {
                    videoContainer.classList.add('vertical');
                } else {
                    videoContainer.classList.add('horizontal');
                }
                
                // Force player size update
                player.dimensions(videoWidth, videoHeight);
                resolve(videoContainer);
            });

            player.on('error', () => {
                reject(new Error('Failed to load video'));
            });

            const cleanup = () => {
                player.dispose();
                videoContainer.remove();
            };

            videoContainer.cleanup = cleanup;
            setTimeout(cleanup, (data.expires_in * 1000) - 1000);
        })
        .catch(error => {
            console.error('Video preview error:', error);
            reject(error);
        });
    });
}

function createAudioPreview(url, headers) {
    return new Promise((resolve, reject) => {
        fetch(url.replace('/preview/', '/preview/audio/'), {
            headers: headers
        })
        .then(response => response.json())
        .then(data => {
            if (!data.url) throw new Error('Invalid preview response');

            // Check if modal exists, if not create it
            let modal = document.getElementById('audioPreviewModal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'audioPreviewModal';
                modal.className = 'audio-preview-modal';
                document.body.appendChild(modal);
            }

            // Initialize HTML structure
            modal.innerHTML = `
                <div class="media-player theme-dark">
                    <div class="media-header">
                        <div class="media-artwork">
                            <i class="fas fa-music"></i>
                        </div>
                        <div class="media-info">
                            <h3 class="media-title"></h3>
                            <p class="media-metadata"></p>
                        </div>
                        <button class="control-button close-btn" onclick="closeAudioPreview()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="media-content">
                        <div class="media-player-content">
                            <video class="video-js"></video>
                        </div>
                        <div class="media-progress">
                            <div class="progress-bar">
                                <div class="progress-handle"></div>
                            </div>
                        </div>
                        <div class="time-display">
                            <span class="time-current">0:00</span>
                            <span class="time-total">0:00</span>
                        </div>
                        <div class="media-controls">
                            <button class="control-button play-button">
                                <i class="fas fa-play"></i>
                            </button>
                        </div>
                        <div class="volume-control">
                            <i class="fas fa-volume-up"></i>
                            <div class="volume-slider">
                                <div class="volume-level" style="width: 50%"></div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Now get references to elements after they're created
            const playerContainer = modal.querySelector('.media-player-content');
            const video = playerContainer.querySelector('video');
            const titleEl = modal.querySelector('.media-title');
            const metadataEl = modal.querySelector('.media-metadata');
            const playBtn = modal.querySelector('.play-button');
            const progressBar = modal.querySelector('.progress-bar');
            const timeCurrent = modal.querySelector('.time-current');
            const timeTotal = modal.querySelector('.time-total');
            const volumeSlider = modal.querySelector('.volume-slider');
            const volumeLevel = modal.querySelector('.volume-level');

            // Initialize video.js player
            const vjsPlayer = videojs(video, {
                controls: false,
                autoplay: false,
                preload: 'auto',
            });

            // Set audio source
            vjsPlayer.src({
                src: data.url,
                type: data.mime_type || 'audio/mp3'
            });

            // Update UI elements
            titleEl.textContent = fileDetails.filename;
            metadataEl.textContent = `Audio • ${fileDetails.file_size}`;

            // Handle play/pause
            playBtn.addEventListener('click', () => {
                if (vjsPlayer.paused()) {
                    vjsPlayer.play();
                    playBtn.querySelector('i').className = 'fas fa-pause';
                } else {
                    vjsPlayer.pause();
                    playBtn.querySelector('i').className = 'fas fa-play';
                }
            });

            // Update progress
            vjsPlayer.on('timeupdate', () => {
                const progress = (vjsPlayer.currentTime() / vjsPlayer.duration()) * 100;
                progressBar.style.width = `${progress}%`;
                timeCurrent.textContent = formatTime(vjsPlayer.currentTime());
            });

            // Set duration
            vjsPlayer.on('loadedmetadata', () => {
                timeTotal.textContent = formatTime(vjsPlayer.duration());
            });

            // Handle progress bar clicks
            modal.querySelector('.media-progress').addEventListener('click', (e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const pos = (e.clientX - rect.left) / rect.width;
                vjsPlayer.currentTime(vjsPlayer.duration() * pos);
            });

            // Handle volume
            volumeSlider.addEventListener('click', (e) => {
                const rect = volumeSlider.getBoundingClientRect();
                const pos = (e.clientX - rect.left) / rect.width;
                vjsPlayer.volume(pos);
                volumeLevel.style.width = `${pos * 100}%`;
            });

            // Show modal
            modal.style.display = 'block';
            setTimeout(() => modal.classList.add('show'), 10);

            // Cleanup function
            const cleanup = () => {
                if (vjsPlayer) {
                    vjsPlayer.dispose();
                }
                modal.classList.remove('show');
                setTimeout(() => {
                    modal.style.display = 'none';
                    playerContainer.innerHTML = ''; // Clear player container
                }, 300);
            };

            modal.cleanup = cleanup;
            resolve(modal);

            // Auto cleanup after expiry
            setTimeout(cleanup, (data.expires_in * 1000) - 1000);
        })
        .catch(error => {
            console.error('Audio preview error:', error);
            reject(error);
        });
    });
}

function closeAudioPreview() {
    const modal = document.getElementById('audioPreviewModal');
    const modalOverlay = document.querySelector('.modal-preview');
    
    if (modal && modal.cleanup) {
        modal.cleanup();
    }
    
    if (modalOverlay) {
        modalOverlay.style.display = 'none';
    }
    
    const previewBtn = document.getElementById('previewBtn');
    if (previewBtn) {
        previewBtn.innerHTML = '<i class="fas fa-eye"></i> Preview';
    }
}

function formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    seconds = Math.floor(seconds % 60);
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

function createPDFPreview(url, headers) {
    return new Promise(async (resolve, reject) => {
        try {
            const pdfUrl = url.replace('/preview/', '/preview/pdf/');
            const response = await fetch(pdfUrl, {
                headers: headers,
                credentials: 'same-origin'
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to get PDF preview URL');
            }
            
            const data = await response.json();
            if (!data.url) throw new Error('Invalid preview response');

            const instanceId = `pdf-${Date.now()}`;
            
            // Initialize PDF viewer variables
            let pdfDoc = null;
            let pageNum = 1;
            const scale = 1.0; // Fixed scale, no zoom

            // Create main container
            const container = document.createElement('div');
            container.className = 'pdf-container';
            
            // Create toolbar with only navigation and fullscreen
            const toolbar = document.createElement('div');
            toolbar.className = 'pdf-toolbar';
            toolbar.innerHTML = `
                <div class="pdf-controls">
                    <button id="prev-${instanceId}" title="Previous page">
                        <i class="fas fa-chevron-left"></i>
                    </button>
                    <div id="page-info-${instanceId}" class="page-info">
                        <span id="page-num-${instanceId}">0</span> / <span id="page-count-${instanceId}">0</span>
                    </div>
                    <button id="next-${instanceId}" title="Next page">
                        <i class="fas fa-chevron-right"></i>
                    </button>
                </div>
                <button id="fullscreen-${instanceId}" title="Toggle fullscreen" class="pdf-fullscreen">
                    <i class="fas fa-expand"></i>
                </button>
            `;
            container.appendChild(toolbar);

            // Add close button
            const closeBtn = document.createElement('button');
            closeBtn.className = 'preview-close-btn';
            closeBtn.innerHTML = '<i class="fas fa-times"></i>';
            closeBtn.onclick = closePreviewModal;
            container.appendChild(closeBtn);

            // Create viewer container
            const viewerContainer = document.createElement('div');
            viewerContainer.className = 'pdf-viewer';
            container.appendChild(viewerContainer);

            // Get references to controls (removed zoom controls)
            const controls = {
                pageNum: toolbar.querySelector(`#page-num-${instanceId}`),
                pageCount: toolbar.querySelector(`#page-count-${instanceId}`),
                prev: toolbar.querySelector(`#prev-${instanceId}`),
                next: toolbar.querySelector(`#next-${instanceId}`),
                fullscreen: toolbar.querySelector(`#fullscreen-${instanceId}`)
            };

            async function renderPage(num) {
                try {
                    pageNum = num;
                    controls.pageNum.textContent = pageNum;
                    
                    const page = await pdfDoc.getPage(pageNum);
                    const viewport = page.getViewport({ scale });
                    
                    let canvas = viewerContainer.querySelector('canvas');
                    if (!canvas) {
                        canvas = document.createElement('canvas');
                        viewerContainer.appendChild(canvas);
                    }
                    
                    const context = canvas.getContext('2d');
                    canvas.height = viewport.height;
                    canvas.width = viewport.width;

                    await page.render({
                        canvasContext: context,
                        viewport: viewport
                    }).promise;

                    // Update controls state
                    controls.prev.disabled = pageNum <= 1;
                    controls.next.disabled = pageNum >= pdfDoc.numPages;
                } catch (error) {
                    console.error('Error rendering page:', error);
                    throw new Error('Failed to render page: ' + error.message);
                }
            }

            // Load PDF and set up controls
            try {
                pdfDoc = await pdfjsLib.getDocument(data.url).promise;
                controls.pageCount.textContent = pdfDoc.numPages;

                // Set up control event handlers
                controls.prev.onclick = () => pageNum > 1 && renderPage(pageNum - 1);
                controls.next.onclick = () => pageNum < pdfDoc.numPages && renderPage(pageNum + 1);

                controls.fullscreen.onclick = () => {
                    if (!document.fullscreenElement) {
                        container.requestFullscreen();
                        controls.fullscreen.innerHTML = '<i class="fas fa-compress"></i>';
                    } else {
                        document.exitFullscreen();
                        controls.fullscreen.innerHTML = '<i class="fas fa-expand"></i>';
                    }
                };

                // Handle keyboard navigation
                const keyHandler = (e) => {
                    if (!container.contains(document.activeElement)) return;
                    
                    switch(e.key) {
                        case 'ArrowLeft':
                            controls.prev.click();
                            break;
                        case 'ArrowRight':
                            controls.next.click();
                            break;
                        case 'f':
                            controls.fullscreen.click();
                            break;
                    }
                };

                document.addEventListener('keydown', keyHandler);
                
                // Handle fullscreen changes
                document.addEventListener('fullscreenchange', () => {
                    controls.fullscreen.innerHTML = document.fullscreenElement ? 
                        '<i class="fas fa-compress"></i>' : 
                        '<i class="fas fa-expand"></i>';
                });

                // Initial render
                await renderPage(1);

                // Cleanup function
                container.cleanup = () => {
                    document.removeEventListener('keydown', keyHandler);
                    document.removeEventListener('fullscreenchange', null);
                    viewerContainer.innerHTML = '';
                    pdfDoc = null;
                };

                resolve(container);

            } catch (error) {
                console.error('PDF preview error:', error);
                reject(error);
            }
        } catch (error) {
            console.error('PDF preview error:', error);
            reject(error);
        }
    });
}

function cleanupPreview() {
    const container = document.getElementById('previewContainer');
    const existingPreview = container.querySelector('img, video, audio, iframe, canvas');
    if (existingPreview) {
        if (existingPreview.parentElement.cleanup) {
            existingPreview.parentElement.cleanup();
        }
        if (existingPreview.src && existingPreview.src.startsWith('blob:')) {
            URL.revokeObjectURL(existingPreview.src);
        }
    }
    container.innerHTML = '';
}
