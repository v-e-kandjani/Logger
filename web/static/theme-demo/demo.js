(function() {
  'use strict';

  const html = document.documentElement;
  const themeToggle = document.getElementById('theme-toggle');
  const menuToggle = document.getElementById('menu-toggle');
  const sidebar = document.getElementById('sidebar');
  const searchInput = document.getElementById('search');
  const severityFilter = document.getElementById('severity');
  const eventRows = document.querySelectorAll('#event-rows tr');
  const resultCount = document.getElementById('result-count');
  const emptyState = document.getElementById('empty-state');
  const resetFilters = document.getElementById('reset-filters');
  const dismissAlert = document.getElementById('dismiss-alert');
  const alertElement = document.getElementById('alert');

  // Theme handling
  function getTheme() {
    try {
      return localStorage.getItem('logseal-theme') || 
             (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    } catch {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
  }

  function setTheme(theme) {
    theme = theme === 'dark' ? 'dark' : 'light';
    html.setAttribute('data-theme', theme);
    if (themeToggle) {
      themeToggle.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
      themeToggle.setAttribute('aria-label', 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' mode');
    }
    try {
      localStorage.setItem('logseal-theme', theme);
    } catch {}
  }

  // Initialize theme
  setTheme(getTheme());

  // Theme toggle handler
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = html.getAttribute('data-theme');
      const newTheme = current === 'light' ? 'dark' : 'light';
      setTheme(newTheme);
      themeToggle.textContent = newTheme === 'dark' ? 'Light Mode' : 'Dark Mode';
    });
  }

  // Menu toggle handler
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => {
      const isOpen = sidebar.classList.contains('is-open');
      sidebar.classList.toggle('is-open');
      menuToggle.setAttribute('aria-expanded', !isOpen);
    });

    // Close sidebar on escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && sidebar.classList.contains('is-open')) {
        sidebar.classList.remove('is-open');
        menuToggle.setAttribute('aria-expanded', false);
        menuToggle.focus();
      }
    });

    // Close sidebar on outside click
    document.addEventListener('click', (e) => {
      if (sidebar.classList.contains('is-open') && 
          !sidebar.contains(e.target) && 
          !menuToggle.contains(e.target)) {
        sidebar.classList.remove('is-open');
        menuToggle.setAttribute('aria-expanded', false);
      }
    });

    // Sidebar link click handler
    sidebar.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        sidebar.classList.remove('is-open');
        menuToggle.setAttribute('aria-expanded', false);
      });
    });
  }

  // Filter events
  function filterEvents() {
    if (!searchInput || !severityFilter || !resultCount || !emptyState) return;
    const searchTerm = searchInput.value.toLowerCase();
    const selectedSeverity = severityFilter.value;
    let visibleCount = 0;

    eventRows.forEach(row => {
      const severity = row.getAttribute('data-severity');
      const textContent = row.textContent.toLowerCase();
      
      const matchesSearch = textContent.includes(searchTerm);
      const matchesSeverity = selectedSeverity === 'all' || severity === selectedSeverity;
      
      row.hidden = !(matchesSearch && matchesSeverity);
      if (!row.hidden) visibleCount++;
    });

    resultCount.textContent = `${visibleCount} of ${eventRows.length} events`;
    emptyState.hidden = visibleCount > 0;
  }

  // Event listeners for filtering
  if (searchInput) searchInput.addEventListener('input', filterEvents);
  if (severityFilter) severityFilter.addEventListener('change', filterEvents);

  // Reset filters
  if (resetFilters && searchInput && severityFilter) {
    resetFilters.addEventListener('click', () => {
      searchInput.value = '';
      severityFilter.value = 'all';
      filterEvents();
    });
  }

  // Dismiss alert
  if (dismissAlert && alertElement) {
    dismissAlert.addEventListener('click', () => {
      alertElement.hidden = true;
      if (searchInput) searchInput.focus();
    });
  }

  // Initialize
  filterEvents();
})();
