// Main JavaScript for Candidate Filtration System

document.addEventListener('DOMContentLoaded', function() {
    // Form submission loading state
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            form.classList.add('form-submitting');
            const submitBtn = form.querySelector('input[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.value = 'Processing...';
            }
        });
    });

    // File upload validation
    const fileInput = document.querySelector('input[type="file"]');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            const file = this.files[0];
            const maxSize = 16 * 1024 * 1024; // 16MB
            const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
            
            if (file) {
                // Check file size
                if (file.size > maxSize) {
                    alert('File size must be less than 16MB');
                    this.value = '';
                    return;
                }
                
                // Check file type
                if (!allowedTypes.includes(file.type)) {
                    alert('Only PDF and Word documents are allowed');
                    this.value = '';
                    return;
                }
                
                // Show file preview
                const fileName = file.name;
                const fileSize = (file.size / 1024 / 1024).toFixed(2) + ' MB';
                
                // Create or update file info display
                let fileInfo = document.querySelector('.file-info');
                if (!fileInfo) {
                    fileInfo = document.createElement('div');
                    fileInfo.className = 'file-info mt-2 p-2 bg-light rounded';
                    this.parentNode.appendChild(fileInfo);
                }
                
                fileInfo.innerHTML = `
                    <small class="text-success">
                        <i class="bi bi-file-earmark-check"></i>
                        Selected: ${fileName} (${fileSize})
                    </small>
                `;
            }
        });
    }

    // Skills input enhancement
    const skillsInput = document.querySelector('textarea[name="skills"], textarea[name="required_skills"]');
    if (skillsInput) {
        skillsInput.addEventListener('input', function() {
            const skills = this.value.split(',').map(skill => skill.trim()).filter(skill => skill);
            const skillCount = skills.length;
            
            let countDisplay = document.querySelector('.skills-count');
            if (!countDisplay) {
                countDisplay = document.createElement('div');
                countDisplay.className = 'skills-count mt-1';
                this.parentNode.appendChild(countDisplay);
            }
            
            countDisplay.innerHTML = `<small class="text-muted">${skillCount} skill${skillCount !== 1 ? 's' : ''} listed</small>`;
        });
    }

    // Phone number formatting
    const phoneInput = document.querySelector('input[name="phone"]');
    if (phoneInput) {
        phoneInput.addEventListener('input', function() {
            // Basic phone number formatting (US format)
            let value = this.value.replace(/\D/g, '');
            if (value.length >= 6) {
                value = value.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
            } else if (value.length >= 3) {
                value = value.replace(/(\d{3})(\d{0,3})/, '($1) $2');
            }
            this.value = value;
        });
    }

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.classList.contains('show')) {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 150);
            }
        }, 5000);
    });

    // Confirmation for form submissions
    const adminForm = document.querySelector('#adminForm');
    if (adminForm) {
        adminForm.addEventListener('submit', function(e) {
            const confirmed = confirm('Are you sure you want to update the filtration criteria? This will affect all future applications.');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    }

    // Tooltip initialization for skill cells
    const skillsCells = document.querySelectorAll('.skills-cell');
    skillsCells.forEach(cell => {
        cell.addEventListener('mouseenter', function() {
            if (this.scrollWidth > this.clientWidth) {
                this.setAttribute('title', this.textContent);
            }
        });
    });
});

// Function to validate email format
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Function to show loading state
function showLoading(element) {
    element.classList.add('form-submitting');
}

// Function to hide loading state
function hideLoading(element) {
    element.classList.remove('form-submitting');
}
