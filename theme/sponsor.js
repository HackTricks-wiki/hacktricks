;(function sponsor() {
  var sponsorSide = document.querySelector(".sidesponsor")
  var sponsorImg = sponsorSide.querySelector(".sidesponsor img")
  var sponsorTitle = sponsorSide.querySelector(".sponsor-title")
  var sponsorDescription = sponsorSide.querySelector(".sponsor-description")
  var sponsorCTA = sponsorSide.querySelector(".sponsor-cta")
  var mobilesponsorSide = document.querySelector(".mobilesponsor")
  var mobilesponsorImg = mobilesponsorSide.querySelector(".mobilesponsor img")
  var mobilesponsorTitle = mobilesponsorSide.querySelector(
    ".mobilesponsor-title"
  )
  var mobilesponsorDescription = mobilesponsorSide.querySelector(
    ".mobilesponsor-description"
  )
  var mobilesponsorCTA = mobilesponsorSide.querySelector(".mobilesponsor-cta")

  async function getSponsor() {
    const url = "https://book.hacktricks.wiki/sponsor"
    try {
      const response = await fetch(url, { method: "GET" })
      if (!response.ok) {
        throw new Error(`Response status: ${response.status}`)
      }

      const json = await response.json()
      var sponsor = json.sponsor
      sponsorImg.src = sponsor.image_url
      sponsorTitle.textContent = sponsor.name
      sponsorDescription.innerHTML = sponsor.description
      sponsorSide.href = sponsor.link
      sponsorCTA.textContent = sponsor.cta
      sponsorSide.style.display = "flex"

      mobilesponsorImg.src = sponsor.image_url
      mobilesponsorTitle.textContent = sponsor.name
      mobilesponsorDescription.innerHTML = sponsor.description
      mobilesponsorSide.href = sponsor.link
      mobilesponsorCTA.textContent = sponsor.cta
      mobilesponsorSide.style.display = "flex"

      if (sponsor.name.length > 45) {
        sponsorTitle.style.fontSize = "1.6rem"
        mobilesponsorTitle.style.fontSize = "1.6rem"
      }

      if (sponsor.description.length > 250) {
        sponsorDescription.style.fontSize = "1.4rem"
        mobilesponsorDescription.style.fontSize = "1.4rem"
      }
    } catch (error) {
      console.error(error.message)
    }
  }

  getSponsor()
})()
