/* ht_searcher.js --------------------------------------------------------- */
(() => {
    const WRAPPER = document.getElementById('search-wrapper');
    const TOGGLE  = document.getElementById('search-toggle');
    const INPUT   = document.getElementById('searchbar');
    const LIST    = document.getElementById('searchresults');
    const HOTKEY  = 83;                // “s”
    let   worker, debounce;
  
    function startWorker() {
      if (worker) return;
      worker = new Worker('/search-worker.js', { type:'module' });
      worker.onmessage = ({data}) => {
        LIST.innerHTML = data.slice(0,30).map(h =>
          `<li><a href="${h.doc.url}">${h.doc.title}</a></li>`
        ).join('');
      };
    }
  
    async function openUI() {
      WRAPPER.classList.remove('hidden');
      INPUT.focus();
      startWorker();                   // fetches CDN/GitHub in parallel
    }
  
    TOGGLE.addEventListener('click', openUI);
    document.addEventListener('keydown', e => {
      if (!e.metaKey && !e.ctrlKey && !e.altKey && e.keyCode === HOTKEY) {
        e.preventDefault(); openUI();
      }
    });
  
    INPUT.addEventListener('input', e => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        worker?.postMessage(e.target.value.trim());
      }, 120);                        // small debounce keeps typing smooth
    });
  })();
  