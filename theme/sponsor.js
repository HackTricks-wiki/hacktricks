;(function sponsor() {
  var sponsorSide = document.querySelector(".sidesponsor")
  var sponsorImg = sponsorSide && sponsorSide.querySelector("img")
  var sponsorTitle = sponsorSide && sponsorSide.querySelector(".sponsor-title")
  var sponsorDescription =
    sponsorSide && sponsorSide.querySelector(".sponsor-description")
  var sponsorCTA = sponsorSide && sponsorSide.querySelector(".sponsor-cta")
  var sponsorSideBsa = document.querySelector(".sidesponsor-bsa")
  var topSponsorBsa = document.querySelector(".topsponsor-bsa")
  var crawlerSlot = document.querySelector(".bsa-crawler-slot")
  var pageviewsSlot = document.querySelector(".bsa-pageviews-slot")

  var topSponsor = document.querySelector(".topsponsor")
  var topSponsorImg = topSponsor && topSponsor.querySelector("img")
  var topSponsorTitle =
    topSponsor && topSponsor.querySelector(".topsponsor-title")
  var topSponsorDescription =
    topSponsor && topSponsor.querySelector(".topsponsor-description")
  var topSponsorCTA =
    topSponsor && topSponsor.querySelector(".topsponsor-cta")

  var bottomSponsor = document.querySelector(".bottomsponsor")
  var bottomSponsorImg = bottomSponsor && bottomSponsor.querySelector("img")
  var bottomSponsorTitle =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-title")
  var bottomSponsorDescription =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-description")
  var bottomSponsorCTA =
    bottomSponsor && bottomSponsor.querySelector(".bottomsponsor-cta")
  var bottomSponsorBsa = document.querySelector(".bottomsponsor-bsa")

  if (
    !sponsorSide ||
    !topSponsor ||
    !bottomSponsor ||
    !sponsorSideBsa ||
    !topSponsorBsa ||
    !crawlerSlot ||
    !pageviewsSlot ||
    !bottomSponsorBsa
  ) {
    return
  }

  var BSA_SCRIPT_BASE = "https://cdn4.buysellads.net/pub/hacktricks.js"
  var BSA_FIXED_LEADERBOARD_FALLBACK = {
    brokenId: "bsa-zone_1773065859037-5_123456",
    actualId: "bsa-zone_1770367111944-8_123456",
  }
  var bsaScriptPromise

  function getBsaScriptSrc() {
    return BSA_SCRIPT_BASE + "?" + (new Date() - (new Date() % 600000))
  }

  function ensureBsaScript() {
    if (bsaScriptPromise) {
      return bsaScriptPromise
    }

    var existingScript = document.querySelector(
      'script[src^="' + BSA_SCRIPT_BASE + '"]'
    )
    if (existingScript) {
      bsaScriptPromise = Promise.resolve(existingScript)
      return bsaScriptPromise
    }

    bsaScriptPromise = new Promise(function(resolve, reject) {
      var originalMapGet = Map.prototype.get
      var restoreMapGet = function() {
        Map.prototype.get = originalMapGet
      }

      Map.prototype.get = function(key) {
        if (
          key === BSA_FIXED_LEADERBOARD_FALLBACK.brokenId &&
          !this.has(key) &&
          this.has(BSA_FIXED_LEADERBOARD_FALLBACK.actualId)
        ) {
          return originalMapGet.call(this, BSA_FIXED_LEADERBOARD_FALLBACK.actualId)
        }

        return originalMapGet.call(this, key)
      }

      var bsaOptimize = document.createElement("script")
      bsaOptimize.type = "text/javascript"
      bsaOptimize.async = true
      bsaOptimize.src = getBsaScriptSrc()
      bsaOptimize.onload = function() {
        restoreMapGet()
        resolve(bsaOptimize)
      }
      bsaOptimize.onerror = function(error) {
        restoreMapGet()
        reject(error)
      }
      ;(
        document.getElementsByTagName("head")[0] ||
        document.getElementsByTagName("body")[0]
      ).appendChild(bsaOptimize)
    })

    return bsaScriptPromise
  }

  function getSponsorTitleFontSize(title) {
    if (title.length > 45) {
      return "1.35rem"
    }

    if (title.length > 28) {
      return "1.55rem"
    }

    return ""
  }

  function resolveSponsorImageUrl(imageUrl) {
    var value = String(imageUrl || "").trim()

    if (!value) {
      return ""
    }

    if (/^https:\/\//i.test(value)) {
      return value
    }

    if (/^\/\//.test(value)) {
      return "https:" + value
    }

    if (value.charAt(0) === "/") {
      return new URL(value, window.location.origin).href
    }

    return new URL(value, document.baseURI || window.location.href).href
  }

  function setLegacySponsorContent(sponsor, container, nodes) {
    nodes.img.src = resolveSponsorImageUrl(sponsor.image_url)
    nodes.img.alt = sponsor.name
    nodes.title.textContent = sponsor.name
    nodes.description.innerHTML = sponsor.description
    container.href = sponsor.link
    nodes.cta.textContent = sponsor.cta
    container.style.display = "grid"
    container.classList.add("ht-sponsor-card--loaded")
    container.setAttribute("aria-label", sponsor.name)

    nodes.title.classList.toggle("sponsor-title--long", sponsor.name.length > 28)
    nodes.title.classList.toggle("ht-sponsor-title--long", sponsor.name.length > 28)
    nodes.title.style.fontSize = getSponsorTitleFontSize(sponsor.name)

    nodes.description.style.fontSize = ""
  }

  function initSponsorCardMotion(card) {
    if (!card) {
      return
    }

    card.addEventListener("mouseenter", function() {
      card.style.setProperty("--sponsor-lift", "-5px")
      card.style.setProperty("--sponsor-scale", "1.02")
    })

    card.addEventListener("mouseleave", function() {
      card.style.setProperty("--sponsor-rx", "0deg")
      card.style.setProperty("--sponsor-ry", "0deg")
      card.style.setProperty("--sponsor-lift", "0px")
      card.style.setProperty("--sponsor-scale", "1")
    })

    card.addEventListener("mousemove", function(event) {
      var rect = card.getBoundingClientRect()
      var x = (event.clientX - rect.left) / rect.width - 0.5
      var y = (event.clientY - rect.top) / rect.height - 0.5

      card.style.setProperty("--sponsor-rx", (-y * 12).toFixed(2) + "deg")
      card.style.setProperty("--sponsor-ry", (x * 12).toFixed(2) + "deg")
    })
  }

  async function fetchLegacySponsor() {
    var currentUrl = encodeURIComponent(window.location.href)
    var url = "https://hacktricks.wiki/sponsor?current_url=" + currentUrl
    var response = await fetch(url, { method: "GET" })

    if (!response.ok) {
      throw new Error("Response status: " + response.status)
    }

    var json = await response.json()
    return json.sponsor
  }

  function renderLegacySideSponsor(sponsor) {
    setLegacySponsorContent(sponsor, sponsorSide, {
      img: sponsorImg,
      title: sponsorTitle,
      description: sponsorDescription,
      cta: sponsorCTA,
    })
  }

  function renderLegacyTopSponsor(sponsor) {
    setLegacySponsorContent(sponsor, topSponsor, {
      img: topSponsorImg,
      title: topSponsorTitle,
      description: topSponsorDescription,
      cta: topSponsorCTA,
    })
  }

  function renderLegacyBottomSponsor(sponsor) {
    setLegacySponsorContent(sponsor, bottomSponsor, {
      img: bottomSponsorImg,
      title: bottomSponsorTitle,
      description: bottomSponsorDescription,
      cta: bottomSponsorCTA,
    })
  }

  async function loadLegacySponsor() {
    var sponsor = await fetchLegacySponsor()
    renderLegacySideSponsor(sponsor)
    renderLegacyTopSponsor(sponsor)
    renderLegacyBottomSponsor(sponsor)
  }

  function shouldUseBsa() {
    var params = new URLSearchParams(window.location.search)
    var forcedProvider = params.get("ads")

    if (forcedProvider === "bsa") {
      return true
    }

    if (forcedProvider === "legacy") {
      return false
    }

    return false
  }

  async function loadBsaSponsor() {
    bottomSponsorBsa.style.display = "block"

    if (window.matchMedia("(min-width: 880px)").matches) {
      sponsorSideBsa.style.display = "block"
      topSponsorBsa.style.display = "none"
    } else {
      sponsorSideBsa.style.display = "none"
      topSponsorBsa.style.display = "block"
    }

    await ensureBsaScript()
  }

  async function initSponsor() {
    ;[sponsorSide, topSponsor, bottomSponsor].forEach(initSponsorCardMotion)

    try {
      var useBsa = shouldUseBsa()
      window.__hacktricksAdsProvider = useBsa ? "bsa" : "legacy"
      console.info("HackTricks ads provider:", window.__hacktricksAdsProvider)

      if (useBsa) {
        await loadBsaSponsor()
        return
      }

      await loadLegacySponsor()
    } catch (error) {
      console.error(error.message || error)

      if (sponsorSideBsa.style.display === "block") {
        sponsorSideBsa.style.display = "none"
      }
      topSponsorBsa.style.display = "none"
      bottomSponsorBsa.style.display = "none"

      try {
        await loadLegacySponsor()
      } catch (legacyError) {
        console.error(legacyError.message || legacyError)
      }
    }
  }

  initSponsor()
})()
