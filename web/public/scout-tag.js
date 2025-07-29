(function () {
  // Create the built by scout tag
  const tag = document.createElement("div");
  tag.id = "built-by-scout";
  tag.innerHTML =
    '<a href="https://scout.new" target="_blank" rel="noopener noreferrer">Built by Scout</a>';

  // Style the tag
  const style = document.createElement("style");
  style.textContent = `
    #built-by-scout {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 8px 16px;
      border-radius: 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      z-index: 9999;
      backdrop-filter: blur(10px);
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      transition: all 0.2s ease;
      opacity: 0;
      animation: fadeIn 0.3s ease forwards;
      animation-delay: 0.5s;
    }
    
    @keyframes fadeIn {
      to {
        opacity: 1;
      }
    }
    
    #built-by-scout:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
      background: rgba(0, 0, 0, 0.9);
    }
    
    #built-by-scout a {
      color: white;
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    
    #built-by-scout a::before {
      content: '✨';
      font-size: 16px;
    }
    
    /* Mobile responsive */
    @media (max-width: 640px) {
      #built-by-scout {
        bottom: 10px;
        right: 10px;
        font-size: 12px;
        padding: 6px 12px;
      }
    }
  `;

  // Add styles and tag to the page
  document.head.appendChild(style);

  // Wait for DOM to be ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      document.body.appendChild(tag);
    });
  } else {
    document.body.appendChild(tag);
  }
})();
