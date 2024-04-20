// anim.js
document.addEventListener("DOMContentLoaded", function() {
    const inputs = document.querySelectorAll('input, select');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.style.backgroundColor = '#e8f0fe';
            this.style.borderColor = '#80bdff';
        });
        input.addEventListener('blur', function() {
            this.style.backgroundColor = '';
            this.style.borderColor = '#ccc';
        });
    });

    const buttons = document.querySelectorAll('button');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.02)';
            this.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.15)';
        });
        button.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
        });
        button.addEventListener('mousedown', function() {
            this.style.transform = 'scale(0.98)';
        });
        button.addEventListener('mouseup', function() {
            this.style.transform = 'scale(1.02)';
        });
    });
});

function simulateUploadProgress() {
    const uploadProgress = document.getElementById('uploadProgress');
    const progressBar = uploadProgress.querySelector('.progress-bar');
    const progressText = document.getElementById('progressText');
    const stages = ['Encrypting', 'Saving', 'Sending'];
    let progress = 0;
    let stageIndex = 0;

    uploadProgress.style.display = 'block';

    const interval = setInterval(() => {
        progress += 10;
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);

        if (progress >= 100) {
            clearInterval(interval);
            progressText.textContent = 'Upload complete!';
        } else if (progress >= (stageIndex + 1) * 33.33) {
            progressText.textContent = stages[stageIndex];
            stageIndex++;
        }
    }, 500);
}

// Call the simulateUploadProgress function when the form is submitted
document.getElementById('uploadForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the form from being submitted immediately
    simulateUploadProgress();
    setTimeout(() => {
        this.submit(); // Submit the form after the animation is complete
    }, 5000); // Adjust the delay as needed to match the animation duration
});