/**
 * caseScope - Main JavaScript
 * Copyright 2025 Justin Dube
 */

// Global variables
let debugEnabled = false;
let currentTheme = localStorage.getItem('theme') || 'dark';
let uploadProgressInterval = null;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeTheme();
    initializeDateTime();
    initializeNavigation();
    initializeFileUpload();
    initializeSearch();
    initializeDebugConsole();
    initializeProgressBars();
});

// Reinitialize upload system on page changes
window.addEventListener('beforeunload', function() {
    if (observer) {
        observer.disconnect();
        observer = null;
    }
});

// Reset upload initialization on navigation
window.addEventListener('popstate', function() {
    console.log('Page navigation detected via popstate, resetting upload system');
    uploadInitialized = false;
    globalClickBlocked = false;
    setTimeout(() => {
        initializeFileUpload();
    }, 100);
});

// Continuous monitoring for upload pages (only check if on upload page)
setInterval(() => {
    if (document.location.pathname.includes('upload_files') && !uploadInitialized) {
        console.log('Periodic upload check triggered - found upload elements');
        initializeFileUpload();
    }
}, 2000);

// Theme Management
function initializeTheme() {
    document.documentElement.setAttribute('data-theme', currentTheme);
    updateThemeIcon();
}

function toggleTheme() {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    localStorage.setItem('theme', currentTheme);
    updateThemeIcon();
    debugLog('Theme switched to: ' + currentTheme);
}

function updateThemeIcon() {
    const themeToggle = document.querySelector('.theme-toggle i');
    if (themeToggle) {
        themeToggle.className = currentTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// Date/Time Display
function initializeDateTime() {
    updateDateTime();
    setInterval(updateDateTime, 1000);
}

function updateDateTime() {
    const datetimeElement = document.getElementById('current-datetime');
    if (datetimeElement) {
        const now = new Date();
        const options = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        };
        datetimeElement.textContent = now.toLocaleDateString('en-US', options);
    }
}

// Navigation
function initializeNavigation() {
    // Dropdown functionality
    const dropdowns = document.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
        const btn = dropdown.querySelector('.dropdown-btn');
        if (btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                toggleDropdown(dropdown);
            });
        }
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.dropdown')) {
            closeAllDropdowns();
        }
    });

    // Load recent cases for dropdown
    loadRecentCases();
}

function toggleDropdown(dropdown) {
    const isActive = dropdown.classList.contains('active');
    closeAllDropdowns();
    
    if (!isActive) {
        dropdown.classList.add('active');
        const chevron = dropdown.querySelector('.fa-chevron-down');
        if (chevron) {
            chevron.style.transform = 'rotate(180deg)';
        }
    }
}

function closeAllDropdowns() {
    const dropdowns = document.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
        dropdown.classList.remove('active');
        const chevron = dropdown.querySelector('.fa-chevron-down');
        if (chevron) {
            chevron.style.transform = 'rotate(0deg)';
        }
    });
}

// File Upload - v7.0.30 Final Chrome fix
let uploadInitialized = false;
let lastUploadClick = 0;
const UPLOAD_CLICK_THRESHOLD = 1500; // 1.5 seconds

function initializeFileUpload() {
    console.log('Initializing file upload v7.0.30');
    
    // Only initialize once
    if (uploadInitialized) {
        console.log('Upload already initialized');
        return;
    }
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeFileUpload);
        return;
    }
    
    // Check if we're on a page with upload functionality
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.querySelector('#file-input');
    
    if (!uploadArea || !fileInput) {
        console.log('No upload elements found on this page');
        return;
    }
    
    console.log('Upload elements found, setting up handlers...');
    setupUploadHandlers(uploadArea, fileInput);
    uploadInitialized = true;
}

function setupUploadHandlers(uploadArea, fileInput) {
    console.log('Setting up upload handlers with Chrome prevention v7.0.31');
    
    let clickInProgress = false;
    
    // Simple, direct click handler
    function handleUploadClick(event) {
        const now = Date.now();
        
        console.log('Upload click detected, time since last:', now - lastUploadClick);
        
        // Prevent rapid successive clicks
        if (now - lastUploadClick < UPLOAD_CLICK_THRESHOLD) {
            console.log('Click ignored - too recent');
            event.preventDefault();
            return false;
        }
        
        // Prevent multiple clicks in progress
        if (clickInProgress) {
            console.log('Click ignored - already in progress');
            event.preventDefault();
            return false;
        }
        
        clickInProgress = true;
        lastUploadClick = now;
        
        console.log('Opening file dialog');
        fileInput.click();
        
        // Reset click progress after a delay
        setTimeout(() => {
            clickInProgress = false;
        }, 1000);
        
        event.preventDefault();
        return false;
    }
    
    // Add file input change handler
    fileInput.addEventListener('change', function(e) {
        console.log('Files selected:', e.target.files.length);
        if (e.target.files.length > 0) {
            // Call the page's handleFileSelection if it exists
            if (typeof window.handleFileSelection === 'function') {
                console.log('Calling window.handleFileSelection');
                window.handleFileSelection(Array.from(e.target.files));
            } else {
                console.error('window.handleFileSelection function not found!');
                // Basic fallback - set files directly
                const selectedFilesDiv = document.getElementById('selected-files');
                if (selectedFilesDiv) {
                    selectedFilesDiv.style.display = 'block';
                    const fileList = document.getElementById('file-list');
                    if (fileList) {
                        fileList.innerHTML = Array.from(e.target.files).map(file => 
                            `<div class="file-item">${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)</div>`
                        ).join('');
                    }
                }
            }
        }
    });
    
    // Add drag and drop handlers
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const files = Array.from(e.dataTransfer.files);
        console.log('Files dropped:', files.length);
        
        if (typeof window.handleFileSelection === 'function') {
            console.log('Calling window.handleFileSelection for drop');
            window.handleFileSelection(files);
        } else {
            console.error('window.handleFileSelection function not found for drop!');
            // Basic fallback for drag and drop
            const selectedFilesDiv = document.getElementById('selected-files');
            if (selectedFilesDiv) {
                selectedFilesDiv.style.display = 'block';
                const fileList = document.getElementById('file-list');
                if (fileList) {
                    fileList.innerHTML = files.map(file => 
                        `<div class="file-item">${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)</div>`
                    ).join('');
                }
            }
        }
    });
    
    // Simple click handler - no cloning, no complex prevention
    uploadArea.addEventListener('click', handleUploadClick);
    
    // Add debugging for upload area clicks
    uploadArea.addEventListener('click', function(e) {
        console.log('Upload area clicked!', e.target);
    }, true); // Use capture phase for debugging
    
    console.log('Upload handlers attached');
    console.log('Upload area element:', uploadArea);
    console.log('File input element:', fileInput);
}

// handleFileSelection function is now provided by the upload template
// Removed duplicate to avoid conflicts

function showSelectedFiles(files) {
    const selectedFilesDiv = document.getElementById('selected-files');
    const fileListDiv = document.getElementById('file-list');
    
    if (selectedFilesDiv && fileListDiv) {
        fileListDiv.innerHTML = '';
        
        Array.from(files).forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'selected-file-item';
            fileItem.innerHTML = `
                <i class="fas fa-file-alt"></i>
                <span class="file-name">${file.name}</span>
                <span class="file-size">${(file.size / 1024 / 1024).toFixed(2)} MB</span>
            `;
            fileListDiv.appendChild(fileItem);
        });
        
        selectedFilesDiv.style.display = 'block';
    }
}

function enableUploadButton() {
    const uploadBtn = document.getElementById('upload-btn');
    const clearBtn = document.getElementById('clear-btn');
    const fileInput = document.querySelector('#file-input');
    const form = document.getElementById('upload-form');
    
    console.log('Enabling upload button and verifying form');
    
    if (uploadBtn) {
        uploadBtn.disabled = false;
        uploadBtn.classList.add('enabled');
        uploadBtn.style.opacity = '1';
        uploadBtn.style.cursor = 'pointer';
        
        // Add click handler to upload button for debugging
        uploadBtn.onclick = function(e) {
            console.log('Upload button clicked');
            console.log('Form found:', !!form);
            console.log('Files in input:', fileInput ? fileInput.files.length : 'No input');
            
            if (fileInput && fileInput.files.length === 0) {
                console.error('No files in input when upload clicked!');
                e.preventDefault();
                alert('Please select files first');
                return false;
            }
            
            console.log('Submitting form...');
            return true; // Allow form submission
        };
        
        console.log('Upload button enabled with click handler');
    } else {
        console.error('Upload button not found!');
    }
    
    if (clearBtn) {
        clearBtn.disabled = false;
        console.log('Clear button enabled');
    }
    
    // Verify file input has files
    if (fileInput) {
        console.log('File input verification - files count:', fileInput.files.length);
        if (fileInput.files.length === 0) {
            console.warn('Warning: File input has no files after selection!');
        }
    }
    
    if (form) {
        console.log('Form found, method:', form.method, 'action:', form.action);
    } else {
        console.error('Upload form not found!');
    }
}

function clearFiles() {
    const fileInput = document.querySelector('input[type="file"]');
    const selectedFilesDiv = document.getElementById('selected-files');
    const uploadBtn = document.getElementById('upload-btn');
    const clearBtn = document.getElementById('clear-btn');
    
    if (fileInput) {
        fileInput.value = '';
    }
    
    if (selectedFilesDiv) {
        selectedFilesDiv.style.display = 'none';
    }
    
    if (uploadBtn) {
        uploadBtn.disabled = true;
        uploadBtn.classList.remove('enabled');
    }
    
    if (clearBtn) {
        clearBtn.disabled = true;
    }
}

function showUploadProgress(files) {
    const progressContainer = document.getElementById('upload-progress');
    if (!progressContainer) return;
    
    progressContainer.innerHTML = '';
    progressContainer.style.display = 'block';
    
    Array.from(files).forEach((file, index) => {
        const progressItem = createProgressItem(file, index);
        progressContainer.appendChild(progressItem);
        
        // Simulate upload progress
        simulateUploadProgress(index, file.size);
    });
}

function createProgressItem(file, index) {
    const item = document.createElement('div');
    item.className = 'upload-progress-item';
    item.innerHTML = `
        <div class="file-info">
            <i class="fas fa-file-alt"></i>
            <div class="file-details">
                <div class="file-name">${file.name}</div>
                <div class="file-size">${formatFileSize(file.size)}</div>
            </div>
        </div>
        <div class="progress-info">
            <div class="progress-status" id="status-${index}">Uploading...</div>
            <div class="progress">
                <div class="progress-bar" id="progress-${index}" style="width: 0%"></div>
            </div>
            <div class="progress-percent" id="percent-${index}">0%</div>
        </div>
    `;
    return item;
}

function simulateUploadProgress(index, fileSize) {
    let progress = 0;
    const progressBar = document.getElementById(`progress-${index}`);
    const progressPercent = document.getElementById(`percent-${index}`);
    const progressStatus = document.getElementById(`status-${index}`);
    
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            progressStatus.textContent = 'Processing...';
            progressBar.classList.add('success');
            
            // Simulate processing
            setTimeout(() => {
                progressStatus.textContent = 'Completed';
            }, 2000);
        }
        
        progressBar.style.width = progress + '%';
        progressPercent.textContent = Math.round(progress) + '%';
    }, 500);
}

// Search Functionality
function initializeSearch() {
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.getElementById('search-btn');
    const searchResults = document.getElementById('search-results');
    
    if (searchInput && searchBtn) {
        searchBtn.addEventListener('click', performSearch);
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
    }
}

function performSearch() {
    const query = document.getElementById('search-input').value.trim();
    const timeRange = document.getElementById('time-range').value;
    const severity = document.getElementById('severity-filter').value;
    
    if (!query) {
        showAlert('warning', 'Please enter a search query.');
        return;
    }
    
    debugLog(`Performing search: ${query}, timeRange: ${timeRange}, severity: ${severity}`);
    
    // Show loading state
    const searchResults = document.getElementById('search-results');
    if (searchResults) {
        searchResults.innerHTML = '<div class="loading">Searching...</div>';
        
        // Simulate search
        setTimeout(() => {
            displaySearchResults([]);
        }, 1000);
    }
}

function displaySearchResults(results) {
    const searchResults = document.getElementById('search-results');
    if (!searchResults) return;
    
    if (results.length === 0) {
        searchResults.innerHTML = '<div class="no-results">No results found.</div>';
        return;
    }
    
    let html = '';
    results.forEach(result => {
        html += `
            <div class="search-result-item">
                <div class="result-header">
                    <span class="result-timestamp">${result.timestamp}</span>
                    <span class="badge badge-${result.severity}">${result.severity}</span>
                </div>
                <div class="result-content">
                    ${result.content}
                </div>
            </div>
        `;
    });
    
    searchResults.innerHTML = html;
}

// Progress Bars
function initializeProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const width = bar.getAttribute('data-width') || '0';
        setTimeout(() => {
            bar.style.width = width + '%';
        }, 100);
    });
}

// Debug Console
function initializeDebugConsole() {
    // Check if debug is enabled from server
    debugEnabled = window.debugEnabled || false;
    
    if (debugEnabled) {
        createDebugConsole();
        debugLog('Debug console initialized');
    }
}

function createDebugConsole() {
    const debugConsole = document.getElementById('debug-console');
    if (debugConsole) {
        debugConsole.style.display = 'block';
    }
}

function debugLog(message) {
    if (!debugEnabled) return;
    
    const debugContent = document.getElementById('debug-content');
    if (debugContent) {
        const timestamp = new Date().toISOString();
        const logEntry = document.createElement('div');
        logEntry.innerHTML = `<span style="color: #888">[${timestamp}]</span> ${message}`;
        debugContent.appendChild(logEntry);
        debugContent.scrollTop = debugContent.scrollHeight;
    }
    
    console.log(`[caseScope] ${message}`);
}

function clearDebugConsole() {
    const debugContent = document.getElementById('debug-content');
    if (debugContent) {
        debugContent.innerHTML = '';
    }
}

function toggleDebugConsole() {
    const debugConsole = document.getElementById('debug-console');
    if (debugConsole) {
        debugConsole.style.display = debugConsole.style.display === 'none' ? 'block' : 'none';
    }
}

// Utility Functions
function formatFileSize(bytes) {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function showAlert(type, message) {
    const alertsContainer = document.querySelector('.content');
    if (!alertsContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <i class="fas fa-${getAlertIcon(type)}"></i>
        ${message}
        <button class="alert-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    alertsContainer.insertBefore(alert, alertsContainer.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 5000);
}

function getAlertIcon(type) {
    const icons = {
        error: 'exclamation-circle',
        success: 'check-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// API Functions
function loadRecentCases() {
    // Cases are now loaded server-side in the template
    // No need for client-side loading anymore
    debugLog('Recent cases loaded from server');
}

function refreshSystemStats() {
    debugLog('Refreshing system statistics...');
    
    // This would make an AJAX call to refresh dashboard stats
    fetch('/api/system/stats')
        .then(response => response.json())
        .then(data => {
            updateSystemStats(data);
            debugLog('System stats updated');
        })
        .catch(error => {
            debugLog('Error loading system stats: ' + error.message);
        });
}

function updateSystemStats(data) {
    // Update various stat elements with new data
    const elements = {
        'case-count': data.caseCount,
        'file-count': data.fileCount,
        'total-size': formatFileSize(data.totalSize),
        'sigma-count': data.sigmaCount,
        'chainsaw-count': data.chainsawCount
    };
    
    Object.keys(elements).forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = elements[id];
        }
    });
}

// Event Handlers
function handleCaseSelection(caseId) {
    debugLog(`Selecting case: ${caseId}`);
    window.location.href = `/select_case/${caseId}`;
}

function handleFileAction(action, fileId) {
    debugLog(`File action: ${action} on file ${fileId}`);
    
    switch (action) {
        case 'reindex':
            if (confirm('Are you sure you want to re-index this file?')) {
                // Make API call to re-index
                showAlert('info', 'File re-indexing started...');
            }
            break;
        case 'rerun-rules':
            if (confirm('Are you sure you want to re-run rules on this file?')) {
                // Make API call to re-run rules
                showAlert('info', 'Rules re-run started...');
            }
            break;
        case 'delete':
            if (confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
                // Make API call to delete
                showAlert('success', 'File deleted successfully.');
            }
            break;
    }
}

function updateRules() {
    debugLog('Updating Sigma and Chainsaw rules...');
    showAlert('info', 'Rule update started...');
    
    // Make API call to update rules
    fetch('/api/rules/update', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', 'Rules updated successfully.');
            } else {
                showAlert('error', 'Rule update failed: ' + data.error);
            }
        })
        .catch(error => {
            showAlert('error', 'Rule update failed: ' + error.message);
        });
}

// Global error handler
window.addEventListener('error', function(e) {
    debugLog(`JavaScript error: ${e.message} at ${e.filename}:${e.lineno}`);
});

// Expose functions globally for inline event handlers
window.toggleTheme = toggleTheme;
window.clearDebugConsole = clearDebugConsole;
window.toggleDebugConsole = toggleDebugConsole;
window.handleCaseSelection = handleCaseSelection;
window.handleFileAction = handleFileAction;
window.updateRules = updateRules;
window.refreshSystemStats = refreshSystemStats;

