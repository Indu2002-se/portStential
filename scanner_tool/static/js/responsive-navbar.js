document.addEventListener('DOMContentLoaded', function() {
    // Mobile menu toggle functionality
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const navLinksContainer = document.querySelector('.nav-links-container');
    
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            // Toggle active class on button for animation
            this.classList.toggle('active');
            
            // Toggle the mobile-active class on nav links
            navLinksContainer.classList.toggle('mobile-active');
            
            // Improve accessibility
            const expanded = navLinksContainer.classList.contains('mobile-active');
            this.setAttribute('aria-expanded', expanded);
        });
    }
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        const isClickInsideNav = event.target.closest('.nav-links-container') || event.target.closest('#mobile-menu-btn');
        
        if (!isClickInsideNav && navLinksContainer.classList.contains('mobile-active')) {
            navLinksContainer.classList.remove('mobile-active');
            if (mobileMenuBtn) {
                mobileMenuBtn.classList.remove('active');
                mobileMenuBtn.setAttribute('aria-expanded', 'false');
            }
        }
    });
    
    // Close menu on window resize (above mobile breakpoint)
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768 && navLinksContainer.classList.contains('mobile-active')) {
            navLinksContainer.classList.remove('mobile-active');
            if (mobileMenuBtn) {
                mobileMenuBtn.classList.remove('active');
                mobileMenuBtn.setAttribute('aria-expanded', 'false');
            }
        }
    });
}); 