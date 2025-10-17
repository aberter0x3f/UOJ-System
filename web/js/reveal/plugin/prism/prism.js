// reveal.js prism plugin

(function() {
	if (typeof window.addEventListener !== 'function' || typeof Prism === 'undefined') {
		return;
	}

	// Select all code blocks
	var codeNodes = document.querySelectorAll('pre code');

	for (var i = 0, len = codeNodes.length; i < len; i++) {
		var element = codeNodes[i];
		var language = null;
		var classesToRemove = [];

		// Find the language declaration in the class list
		for (var k = 0; k < element.classList.length; k++) {
			var cls = element.classList[k];
			var match;

			if (match = cls.match(/^language-(.+)/)) {
				language = match[1];
				// This class is already correct, no need to modify
				break;
			}
			if (match = cls.match(/^lang-(.+)/)) {
				language = match[1];
				classesToRemove.push(cls);
				break;
			}
			if (match = cls.match(/^sh_(.+)/)) {
				language = match[1];
				classesToRemove.push(cls);
				break;
			}
		}

		// If no prefixed class was found, assume the first class is the language name
		if (!language && element.classList.length > 0) {
			// This handles cases like <code class="cpp">
			language = element.classList[0];
			classesToRemove.push(language);
		}

		if (language) {
			// Normalize language name (e.g., c++ to cpp)
			if (language === 'c++') {
				language = 'cpp';
			}
			
			// Clean up old, non-standard classes
			classesToRemove.forEach(function(cls) {
				element.classList.remove(cls);
			});

			// Ensure the correct Prism class is present
			if (!element.classList.contains('language-' + language)) {
				element.classList.add('language-' + language);
			}
		}

		// trim whitespace if data-trim attribute is present
		if (element.hasAttribute('data-trim') && typeof element.textContent.trim === 'function') {
			element.textContent = element.textContent.trim();
		}

		// Highlight the code block now that classes are correct
		Prism.highlightElement(element);

		// re-highlight when focus is lost (for editable code)
		element.addEventListener('focusout', function(event) {
			Prism.highlightElement(event.currentTarget);
		}, false);
	}
})();