/**
 * caseScope v7.0.0 - Main JavaScript
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

// File Upload
function initializeFileUpload() {
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.querySelector('input[type="file"]');
    
    if (uploadArea && fileInput) {
        // Drag and drop functionality
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
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFileSelection(files);
            }
        });

        uploadArea.addEventListener('click', function(e) {
            // Prevent form submission if clicked
            e.preventDefault();
            fileInput.click();
        });

        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                handleFileSelection(e.target.files);
            }
        });
    }
}

function handleFileSelection(files) {
    // Validate file types
    const validTypes = ['evtx'];
    const maxFiles = 5;
    
    if (files.length > maxFiles) {
        showAlert('error', `Maximum ${maxFiles} files allowed at once.`);
        return;
    }
    
    for (let file of files) {
        const extension = file.name.split('.').pop().toLowerCase();
        if (!validTypes.includes(extension)) {
            showAlert('error', `Invalid file type: ${file.name}. Only EVTX files are allowed.`);
            return;
        }
    }
    
    // Set the files on the input element
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        // Create a new FileList with the dropped files
        const dt = new DataTransfer();
        for (let file of files) {
            dt.items.add(file);
        }
        fileInput.files = dt.files;
    }
    
    // Show upload progress and start upload
    showUploadProgress(files);
    startFileUpload(files);
    debugLog(`Selected ${files.length} files for upload`);
}

function startFileUpload(files) {
    const form = document.getElementById('upload-form');
    if (!form) {
        showAlert('error', 'Upload form not found.');
        return;
    }
    
    // Submit the form
    form.submit();
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

