;(function discount() {
  var CAMPAIGN_ID = "summer-2026"
  var DISMISS_KEY = "htDiscountDismissedUntil:" + CAMPAIGN_ID
  var DISMISS_MS = 10 * 24 * 60 * 60 * 1000
  var IMAGE_PATH = "images/hacktricks-summer-discount-2026.png"
  var TARGET_URL = "https://hacktricks-training.com"
  var TITLE = "HackTricks Training Summer Discount"

  function storageGet(key) {
    try {
      return window.localStorage.getItem(key)
    } catch (error) {
      return null
    }
  }

  function storageSet(key, value) {
    try {
      window.localStorage.setItem(key, value)
    } catch (error) {}
  }

  function getParam(name) {
    try {
      return new URLSearchParams(window.location.search).get(name)
    } catch (error) {
      return null
    }
  }

  function shouldReduceMotion() {
    return Boolean(
      document.documentElement.classList.contains("motion-reduced") ||
        (window.__hacktricksMotion &&
          window.__hacktricksMotion.shouldReduceMotion &&
          window.__hacktricksMotion.shouldReduceMotion()) ||
        (window.matchMedia &&
          window.matchMedia("(prefers-reduced-motion: reduce)").matches)
    )
  }

  function getAssetUrl(path) {
    var root = typeof window.path_to_root === "string" ? window.path_to_root : ""
    return new URL(root + path, document.baseURI || window.location.href).href
  }

  function isDismissed() {
    if (getParam("discount") === "show") {
      return false
    }

    var dismissedUntil = Number(storageGet(DISMISS_KEY))
    return Number.isFinite(dismissedUntil) && Date.now() < dismissedUntil
  }

  function close(overlay, onKeydown) {
    overlay.classList.remove("ht-discount-overlay--visible")
    if (onKeydown) {
      document.removeEventListener("keydown", onKeydown)
    }
    window.setTimeout(function() {
      overlay.remove()
    }, 220)
  }

  function dismissFor15Days(overlay, onKeydown) {
    storageSet(DISMISS_KEY, String(Date.now() + DISMISS_MS))
    close(overlay, onKeydown)
  }

  function initMotion(card) {
    if (!card || shouldReduceMotion()) {
      return
    }

    card.addEventListener("mouseenter", function() {
      card.style.setProperty("--discount-lift", "-5px")
      card.style.setProperty("--discount-scale", "1.01")
    })

    card.addEventListener("mouseleave", function() {
      card.style.setProperty("--discount-rx", "0deg")
      card.style.setProperty("--discount-ry", "0deg")
      card.style.setProperty("--discount-lift", "0px")
      card.style.setProperty("--discount-scale", "1")
      card.style.setProperty("--discount-img-x", "0px")
      card.style.setProperty("--discount-img-y", "0px")
    })

    card.addEventListener("mousemove", function(event) {
      var rect = card.getBoundingClientRect()
      var x = (event.clientX - rect.left) / rect.width - 0.5
      var y = (event.clientY - rect.top) / rect.height - 0.5

      card.style.setProperty("--discount-rx", (-y * 9).toFixed(2) + "deg")
      card.style.setProperty("--discount-ry", (x * 9).toFixed(2) + "deg")
      card.style.setProperty("--discount-img-x", (x * 10).toFixed(2) + "px")
      card.style.setProperty("--discount-img-y", (y * 10).toFixed(2) + "px")
    })
  }

  function createDiscount() {
    if (isDismissed() || document.querySelector(".ht-discount-overlay")) {
      return
    }

    var overlay = document.createElement("div")
    overlay.className = "ht-discount-overlay"
    overlay.setAttribute("role", "dialog")
    overlay.setAttribute("aria-modal", "true")
    overlay.setAttribute("aria-label", TITLE)

    var card = document.createElement("div")
    card.className = "ht-discount-card"

    var grid = document.createElement("span")
    grid.className = "ht-discount-grid"
    grid.setAttribute("aria-hidden", "true")

    var scan = document.createElement("span")
    scan.className = "ht-discount-scan"
    scan.setAttribute("aria-hidden", "true")

    var corners = document.createElement("span")
    corners.className = "ht-discount-corners"
    corners.setAttribute("aria-hidden", "true")

    var kicker = document.createElement("span")
    kicker.className = "ht-discount-kicker"
    kicker.textContent = "Summer offer"

    var closeButton = document.createElement("button")
    closeButton.className = "ht-discount-close"
    closeButton.type = "button"
    closeButton.setAttribute("aria-label", "Close discount offer")
    closeButton.textContent = "x"

    var imageLink = document.createElement("a")
    imageLink.className = "ht-discount-link"
    imageLink.href = TARGET_URL
    imageLink.target = "_blank"
    imageLink.rel = "noopener noreferrer"
    imageLink.setAttribute("aria-label", TITLE)

    var image = document.createElement("img")
    image.className = "ht-discount-image"
    image.src = getAssetUrl(IMAGE_PATH)
    image.alt = TITLE
    image.decoding = "async"

    var actions = document.createElement("div")
    actions.className = "ht-discount-actions"

    var primary = document.createElement("a")
    primary.className = "ht-discount-primary"
    primary.href = TARGET_URL
    primary.target = "_blank"
    primary.rel = "noopener noreferrer"
    primary.textContent = "Open offer"

    var delayButton = document.createElement("button")
    delayButton.className = "ht-discount-delay"
    delayButton.type = "button"
    delayButton.textContent = "Hide for 10 days"

    imageLink.appendChild(image)
    actions.append(primary, delayButton)
    card.append(grid, scan, corners, kicker, closeButton, imageLink, actions)
    overlay.appendChild(card)
    document.body.appendChild(overlay)

    initMotion(card)

    function onKeydown(event) {
      if (event.key === "Escape" && overlay.isConnected) {
        close(overlay, onKeydown)
      }
    }

    closeButton.addEventListener("click", function() {
      close(overlay, onKeydown)
    })

    delayButton.addEventListener("click", function() {
      dismissFor15Days(overlay, onKeydown)
    })

    overlay.addEventListener("click", function(event) {
      if (event.target === overlay) {
        close(overlay, onKeydown)
      }
    })

    document.addEventListener("keydown", onKeydown)

    window.setTimeout(function() {
      overlay.classList.add("ht-discount-overlay--visible")
    }, 80)
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", createDiscount, { once: true })
  } else {
    createDiscount()
  }
})()
