use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio;

#[derive(Deserialize, Debug)]
struct CVE {
    id: String,
    description: Option<String>,
    // You can expand this based on NVD JSON response structure
}

#[derive(Deserialize, Debug)]
struct MitreTechnique {
    id: String,
    name: String,
    description: String,
    // You can expand this based on MITRE API structure
}

async fn fetch_cves() -> Result<Vec<CVE>, reqwest::Error> {
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    let client = Client::new();
    let response = client.get(url).send().await?.json::<Vec<CVE>>().await?;
    Ok(response)
}

async fn fetch_mitre_techniques(apt_group: &str) -> Result<Vec<MitreTechnique>, reqwest::Error> {
    let url = format!("https://api.mitre.org/v2/techniques?group={}", apt_group);
    let client = Client::new();
    let response = client.get(&url).send().await?.json::<Vec<MitreTechnique>>().await?;
    Ok(response)
}

async fn query_cti_data(apt_group: &str) -> Result<(), Box<dyn Error>> {
    println!("🔍 Fetching data for APT Group: {}", apt_group);

    // Fetch CVEs
    let cves = fetch_cves().await?;
    println!("📉 Latest CVEs:");
    for cve in cves.iter() {
        println!("- {}: {}", cve.id, cve.description.as_deref().unwrap_or("No description"));
    }

    // Fetch MITRE Techniques
    let techniques = fetch_mitre_techniques(apt_group).await?;
    println!("\n⚔️ Techniques used by {}:", apt_group);
    for technique in techniques.iter() {
        println!("- {}: {}", technique.id, technique.name);
        println!("  Description: {}", technique.description);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    println!("🔍 CTI Chatbot Booting...");
    let apt_group = "APT41"; // Example group; you can make this dynamic

    if let Err(err) = query_cti_data(apt_group).await {
        eprintln!("Error: {}", err);
    }
}
