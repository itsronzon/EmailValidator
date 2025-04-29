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
        document.getElementById('score-breakdown').innerHTML = '';
        
        // Display verdict badge
        if (results.is_deliverable) {
            resultVerdict.textContent = 'DELIVERABLE';
            resultVerdict.className = 'float-end badge bg-success';
        } else {
            resultVerdict.textContent = 'UNDELIVERABLE';
            resultVerdict.className = 'float-end badge bg-danger';
        }
        
        // Display score gauge
        const scoreGauge = document.getElementById('score-gauge');
        const scoreValue = results.score || 0;
        scoreGauge.style.width = `${scoreValue}%`;
        scoreGauge.setAttribute('aria-valuenow', scoreValue);
        scoreGauge.textContent = `${scoreValue}%`;
        
        // Set color based on score
        if (scoreValue >= 80) {
            scoreGauge.className = 'progress-bar bg-success';
        } else if (scoreValue >= 50) {
            scoreGauge.className = 'progress-bar bg-warning';
        } else {
            scoreGauge.className = 'progress-bar bg-danger';
        }
        
        // Set score description
        const scoreDescription = document.getElementById('score-description');
        if (scoreValue >= 80) {
            scoreDescription.innerHTML = '<strong class="text-success">High deliverability</strong> - Email is likely valid and will be delivered';
        } else if (scoreValue >= 50) {
            scoreDescription.innerHTML = '<strong class="text-warning">Medium deliverability</strong> - Email might be valid but has some issues';
        } else {
            scoreDescription.innerHTML = '<strong class="text-danger">Low deliverability</strong> - Email is likely invalid or undeliverable';
        }
        
        // Display score breakdown if available
        if (results.score_details) {
            const scoreBreakdown = document.getElementById('score-breakdown');
            
            // Create items for each score component
            Object.entries(results.score_details).forEach(([key, value]) => {
                if (value !== 0) { // Only show non-zero components
                    const item = document.createElement('li');
                    item.className = 'list-group-item bg-dark text-white border-secondary';
                    
                    // Format the key name
                    const formattedKey = key.replace(/_/g, ' ');
                    
                    // Set positive or negative indicator
                    let indicator = '';
                    let valueClass = '';
                    if (value > 0) {
                        indicator = '<i class="fas fa-plus-circle text-success me-2"></i>';
                        valueClass = 'text-success';
                    } else {
                        indicator = '<i class="fas fa-minus-circle text-danger me-2"></i>';
                        valueClass = 'text-danger';
                    }
                    
                    item.innerHTML = `${indicator}<span class="text-capitalize">${formattedKey}:</span> <span class="float-end ${valueClass}">${value > 0 ? '+' : ''}${value}</span>`;
                    scoreBreakdown.appendChild(item);
                }
            });
            
            // Add total score
            const totalItem = document.createElement('li');
            totalItem.className = 'list-group-item bg-dark text-white border-secondary fw-bold';
            totalItem.innerHTML = `<span>Total Score:</span> <span class="float-end">${results.score}/100</span>`;
            scoreBreakdown.appendChild(totalItem);
        }
        
        // Add rows for each verification step
        if (results.verification_steps && results.verification_steps.length > 0) {
            results.verification_steps.forEach(step => {
                const row = document.createElement('tr');
                
                // Step name (capitalized)
                const stepName = step.step.replace('_check', '').replace(/_/g, ' ');
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
            case 'disposable_check':
                return 'fas fa-recycle';
            case 'popular_domain_check':
                return 'fas fa-star';
            case 'pattern_check':
                return 'fas fa-fingerprint';
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
