import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # Use a standard 1080p resolution
        page = await browser.new_page(viewport={'width': 1920, 'height': 1080})
        
        print("1. Navigating to FUSIONX UI...")
        await page.goto("http://localhost:5173/")
        await page.wait_for_timeout(2000) # Let animations load
        
        # Take Empty State Screenshot
        print("2. Capturing Dashboard Screenshot...")
        await page.screenshot(path="ui_01_dashboard.png", full_page=True)
        
        # Start a scan to capture scanning state
        print("3. Starting a scan on FUSIONX repo...")
        # Assuming there is an input field for target and a submit button
        # Based on typical UI, let's try to find an input and button.
        try:
            # Let's just enter text into any visible text input
            await page.fill('input[type="text"]', "https://github.com/printezz01/FUSIONX-")
            # And click any button that says "Scan" or similar
            await page.click('button:has-text("Scan"), button:has-text("Start"), button[type="submit"]')
            await page.wait_for_timeout(2000)
            
            print("4. Capturing Scanning State Screenshot...")
            await page.screenshot(path="ui_02_scanning.png", full_page=True)
            
            # Wait for scan to finish (let's wait up to 45 seconds)
            print("5. Waiting for scan to finish...")
            await page.wait_for_timeout(35000)
            
            print("6. Capturing Results Screenshot...")
            await page.screenshot(path="ui_03_results.png", full_page=True)
        except Exception as e:
            print(f"Could not automate scan flow (maybe selectors didn't match): {e}")
            
        await browser.close()
        print("All screenshots saved to FUSIONX folder.")

if __name__ == "__main__":
    asyncio.run(main())
