require("dotenv").config();
const axios = require("axios");
const mongoose = require("mongoose");
const CVE = require("./models/CVE");

const fetchCVEs = async () => {
  try {
    const response = await axios.get(
      "https://services.nvd.nist.gov/rest/json/cves/2.0",
      {
        params: { resultsPerPage: 10 },
      }
    );

    console.log("API Data:", response.data);
    if (response.data && response.data.vulnerabilities) {
      return response.data.vulnerabilities;
    }
    return [];
  } catch (error) {
    console.error("Error fetching CVE data:", error);
    return [];
  }
};

const storeCVEs = async (cveData) => {
  try {
    await mongoose.connect(process.env.DB_URI);
    const inserted = await CVE.insertMany(cveData);
    console.log(`Inserted ${inserted.length} new records.`);
  } catch (error) {
    console.error("Error storing CVEs to MongoDB:", error);
  } finally {
    mongoose.disconnect();
  }
};

async function processCVEs() {
  try {
    const data = await fetchCVEs();
    console.log("sss", typeof data);
    const transformedData = data.map((item) => {
      console.log("Received CVE Item:", item.cve);
      const { cve } = item;

      if (!cve) {
        console.error("CVE object is undefined.");
        return null;
      }

      const cveData = {
        id: cve.id,
        sourceIdentifier: cve.sourceIdentifier,
        published: new Date(cve.published),
        lastModified: new Date(cve.lastModified),
        vulnStatus: cve.vulnStatus,
        descriptions: cve.descriptions,
        metrics: cve.metrics,
        weaknesses: cve.weaknesses,
        configurations: cve.configurations,
        references: cve.references,
      };

      console.log("Transformed CVE Data:", cveData);
      return cveData;
    });
    await storeCVEs(transformedData);
  } catch (error) {
    console.error("Error in processing CVEs:", error);
  }
}

processCVEs();
