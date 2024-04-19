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
