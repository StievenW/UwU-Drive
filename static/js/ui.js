// Menu and form handling
function toggleForm(formId) {
    // Get all menu items and forms
    const menuItems = document.querySelectorAll('.menu-item');
    const forms = document.querySelectorAll('.menu-form');
    const clickedMenuItem = document.querySelector(`.menu-item[onclick*="${formId}"]`);
    const targetForm = document.getElementById(formId);

    // First hide all forms and remove active class from menu items
    menuItems.forEach(item => item.classList.remove('active'));
    forms.forEach(form => form.classList.remove('active'));

    // Then show the selected form and activate menu item
    if (clickedMenuItem && targetForm) {
        clickedMenuItem.classList.add('active');
        targetForm.classList.add('active');
        
        // Ensure smooth animation
        setTimeout(() => {
            targetForm.style.opacity = '1';
            targetForm.style.transform = 'translateY(0)';
        }, 0);
    }
}

// Initialize UI
document.addEventListener('DOMContentLoaded', function() {
    // Show search form by default instead of upload form
    toggleForm('search_form');

    // Update active state on menu icons
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        // Remove active class from upload menu
        if(item.getAttribute('onclick').includes('upload_form')) {
            item.classList.remove('active');
        }
        // Add active class to search menu
        if(item.getAttribute('onclick').includes('search_form')) {
            item.classList.add('active');
        }
    });

    // Setup menu click handlers
    menuItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const formId = this.getAttribute('onclick').match(/'(.*?)'/)[1];
            toggleForm(formId);
        });
    });

    // Setup search input handler
    const searchInput = document.getElementById('search_input');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(function(e) {
            const query = e.target.value.trim();
            searchFiles(e);
        }, 500));
        
        // Focus search input by default
        searchInput.focus();
    }
});

// Add debounce function to prevent too many searches
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
