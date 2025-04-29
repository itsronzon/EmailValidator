document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('verification-form');
    const loading = document.getElementById('loading');
    const resultsContainer = document.getElementById('results-container');
    const resultsTable = document.getElementById('results-table');
    const resultEmail = document.getElementById('result-email');
    const resultVerdict = document.getElementById('result-verdict');

    form.addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('email').value.trim();
        
        if (!email) {
            showAlert('Please enter an email address', 'danger');
            return;
        }
        
        // Show loading spinner
        loading.style.display = 'block';
        resultsContainer.style.display = 'none';
        
        // Send verification request
        const formData = new FormData();
        formData.append('email', email);
        
        fetch('/verify', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            // Hide loading spinner
            loading.style.display = 'none';
            
            if (data.success) {
                // Display results
                displayResults(data.results);
            } else {
                showAlert(data.message || 'Verification failed', 'danger');
            }
        })
        .catch(error => {
            loading.style.display = 'none';
            showAlert('Error: ' + error.message, 'danger');
        });
    });
    
    function displayResults(results) {
        // Display the email address
        resultEmail.textContent = results.email;
        
        // Clear previous results
        resultsTable.innerHTML = '';
        
        // Display verdict badge
        if (results.is_deliverable) {
            resultVerdict.textContent = 'DELIVERABLE';
            resultVerdict.className = 'float-end badge bg-success';
        } else {
            resultVerdict.textContent = 'UNDELIVERABLE';
            resultVerdict.className = 'float-end badge bg-danger';
        }
        
        // Add rows for each verification step
        if (results.verification_steps && results.verification_steps.length > 0) {
            results.verification_steps.forEach(step => {
                const row = document.createElement('tr');
                
                // Step name (capitalized)
                const stepName = step.step.replace('_check', '').replace('_', ' ');
                const stepCell = document.createElement('td');
                stepCell.innerHTML = `<i class="${getStepIcon(step.step)} me-2"></i>${capitalizeFirstLetter(stepName)}`;
                row.appendChild(stepCell);
                
                // Status
                const statusCell = document.createElement('td');
                if (step.passed) {
                    statusCell.innerHTML = '<span class="badge bg-success">PASSED</span>';
                } else {
                    statusCell.innerHTML = '<span class="badge bg-danger">FAILED</span>';
                }
                row.appendChild(statusCell);
                
                // Details
                const detailsCell = document.createElement('td');
                detailsCell.textContent = step.message;
                row.appendChild(detailsCell);
                
                resultsTable.appendChild(row);
            });
        }
        
        // Show results container
        resultsContainer.style.display = 'block';
        
        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
    
    function getStepIcon(step) {
        switch(step) {
            case 'syntax_check':
                return 'fas fa-code';
            case 'domain_check':
                return 'fas fa-globe';
            case 'mx_check':
                return 'fas fa-server';
            default:
                return 'fas fa-check-circle';
        }
    }
    
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
    
    function showAlert(message, type) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert before the form
        form.parentNode.insertBefore(alertDiv, form);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 300);
        }, 5000);
    }
});
