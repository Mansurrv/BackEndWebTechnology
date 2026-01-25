// Debounce function to prevent too many requests
let debounceTimer;

function debounce(func, delay) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(func, delay);
}

// Function to perform search
async function performSearch() {
    const searchInput = document.getElementById('search-input');
    const resultsDiv = document.getElementById('results');
    const query = searchInput.value.trim();
    
    if (!query) {
        resultsDiv.innerHTML = '';
        return;
    }
    
    try {
        // Show loading indicator
        resultsDiv.innerHTML = '<div class="loading">Searching...</div>';
        
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        displayResults(data);
    } catch (error) {
        console.error('Search error:', error);
        resultsDiv.innerHTML = '<div class="error">Error performing search. Please try again.</div>';
    }
}

// Function to display results
function displayResults(results) {
    const resultsDiv = document.getElementById('results');
    
    if (!results || results.length === 0) {
        resultsDiv.innerHTML = '<div class="no-results">No results found.</div>';
        return;
    }
    
    const html = results.map(item => `
        <div class="result-item">
            <a href="${item.url}">
                <h3>${item.title}</h3>
                <p>${item.description}</p>
            </a>
        </div>
    `).join('');
    
    resultsDiv.innerHTML = html;
}

// Initialize search functionality
document.addEventListener('DOMContentLoaded', function() {
    const searchForm = document.querySelector('.searchh');
    const searchInput = document.getElementById('search-input');
    const resultsDiv = document.getElementById('results');
    
    if (!searchInput || !resultsDiv) return;
    
    // Handle form submission
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            performSearch();
        });
    }
    
    // Handle real-time typing
    searchInput.addEventListener('input', function() {
        if (this.value.length >= 2) { // Start searching after 2 characters
            debounce(performSearch, 300);
        } else {
            resultsDiv.innerHTML = '';
        }
    });
    
    // Close results when clicking outside
    document.addEventListener('click', function(e) {
        if (!searchForm.contains(e.target)) {
            resultsDiv.innerHTML = '';
        }
    });
});