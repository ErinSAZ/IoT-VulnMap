# Research

## Table of Contents
- [Home Assistant API](#home-assistant-api)
  - [Overview](#overview)
  - [Findings](#findings)
  - [Limitations & observations](#limitations--observations)
- [CIRCL Vulnerability Lookup API](#circl-vulnerability-lookup-api)
  - [Approach 1 - Web Scraping](#approach-1---web-scraping)
    - [Overview](#overview-1)
    - [Findings](#findings-1)
    - [Limitations & observations](#limitations--observations-1)
  - [Approach 2 - JSON API](#approach-2---json-api)
    - [Overview](#overview-2)
    - [Findings](#findings-2)
    - [Limitations & observations](#limitations--observations-2)
- [References](#references)

## Home Assistant API

### Overview
Home Assistant is an open-source home automation platform that allow users to manage and monitor their IoT devices 
locally. It exposes a WebSocket API that allows external applications to interact with the platform and retrieve
information about connected devices, their states, and other relevant data.

We use this API to retrieve the list of devices registered in the user's Home Assistant instance, along with their
associated metadata such as vendor, product, firmware version. This information is crucial for identifying potential
vulnerabilities in the devices and providing relevant security recommendations.

### Findings
Home Assistant exposes a WebSocket API that requires authentication via a long-lived access token. Once authenticated, 
we used the 'device_registry/list' command to retrieve a list of all devices registered in the Home Assistant instance. 
Each device entry contains various attributes, including the vendor, product, and firmware version, which are essential
for our vulnerability lookup process. We also implemented error handling to manage potential issues such as connection 
failures, authentication errors, and unexpected responses from the API. The retrieved device information is then used as
input for querying the CIRCL Vulnerability Lookup API to identify any known vulnerabilities associated with the devices.

For each device, the following fields were extracted :

| Field | Description |
|-------|-------------|
| `manufacturer` | The vendor/brand of the device |
| `model` | The product name |
| `sw_version` | The firmware version |
| `name` | The user-defined or default device name |

The results were saved to a JSON file for further processing and analysis.

### Limitations & observations
Some fields (manufacturer, model etc) are ofte missing or set to null depending on how the device was integrated into
Home Assistant. This can make it difficult to accurately identify the device and retrieve relevant vulnerability 
information. Additionally, the 'manufacturer' and 'model' fields are not standardized, the same vendor can appear under
different names. Also, the API requires the Home Assistant instance to be accessible on the local network, which limits
the portability of the tool.

### Results
The script successfully retrieved the list of devices from the Home Assistant instance, along with their associated 
metadata. The extracted information was saved to the `ha_devices_example` JSON file, which can be used for further 
processing and analysis. This data serves as the basis for querying the CIRCL Vulnerability Lookup API to identify 
potential vulnerabilities associated with the devices in the user's Home Assistant instance.

---

## CIRCL Vulnerability Lookup API

### Approach 1 - Web Scraping

#### Overview
CIRCL (Computer Incident Response Center Luxembourg) is a government-driven initiative that provides security services
and resources to help organizations protect their digital assets. One of the services they offer is a vulnerability 
lookup website, which allows users to search for known vulnerabilities based on various parameters such as vendor, 
product, and firmware version. This website provides a valuable resource for identifying potential vulnerabilities in 
IoT devices, as it aggregates information from various sources and provides a centralized platform for vulnerability 
information.

As a first approach, we explored CICL's Vulnerability Lookup instance by directly scraping the HTML results page. This 
approach involved sending HTTP requests to the CIRCL website with the appropriate query parameters (vendor, product, 
firmware version) and parsing the HTML response to extract the relevant vulnerability information. This method allowed 
us to quickly access the vulnerability data without needing to set up API authentication or handle structured data 
formats. However, it also presented challenges such as handling changes in the website's structure, dealing with 
potential rate limits, and ensuring that the scraping process was efficient and reliable.

#### Findings
By analyzing the CIRCL Vulnerability Lookup results page, we found that the number of vulnerabilities associated with a
given vendor was displayed in a '\<h2\>' tag with the class 'mt-4'. By extracting the first word of this tag, we were
able to retrieve the total count of vulnerabilities for each vendor.

We also had a realistic 'User-Agent' header in the requests to prevent the server from rejecting our requests, as well
as a delay of 0.5 seconds between each request to avoid overwhelming the server and to mimic human browsing behavior.

The script successfully retrieved the number of vulnerabilities for each vendor present in the Home Assistant device 
list.

#### Limitations & observations
The scrapping is not very reliable, as the structure of the HTML page can change, which would break our parsing logic.
Additionally, this approach may not be as efficient as using a structured API, as it requires additional processing to
extract the relevant information from the HTML response. Furthermore, there may be limitations on the number of requests 
that can be made to the CIRCL website, which could impact the performance of our application if we need to retrieve 
vulnerability information for a large number of devices.

### Results
The script successfully retrieved the number of vulnerabilities for each vendor present in the Home Assistant device 
list. The results are like the following:

| Vendor                         | CVE count |
|--------------------------------|-----------|
| Risco                          | 0         |
| N/A                            | 0         |
| Google Inc.                    | 960       |
| Tuya                           | 8         |
| Home Assistant Community Store | 0         |
| Apple                          | 8324      |
| IKEA of Sweden                 | 0         |
| Home Assistant Community Apps  | 0         |
| Sony                           | 51        |
| Freebox                        | 0         |

---

### Approach 2 - JSON API

#### Overview
As a second approach, we used this API to retrieve the list of products associated with a given vendor, in order to
verify that our device data could be matched against the CIRCL database and retrieve relevant vulnerability information.
This approach allows us to leverage the structured data provided by the CIRCL API, which can be more reliable and easier
to work with compared to web scraping. By querying the API with the vendor information obtained from the Home Assistant
API, we can retrieve a list of products associated with that vendor, and then further query for specific vulnerabilities 
based on the product and firmware version. This approach enables us to provide more accurate and comprehensive 
vulnerability information to the user, based on the data retrieved from their Home Assistant instance.

#### Findings
The CIRCL Vulnerability Lookup API provides an endpoint to retrieve a list of products associated with a given vendor.
By sending a GET request to this endpoint with the appropriate vendor parameter, we were able to retrieve a JSON 
response containing the list of products. This allowed us to verify that the device data obtained from the Home 
Assistant API could be matched against the CIRCL database, and that we could retrieve relevant vulnerability information
based on the product and firmware version. The API response included various details about each product, such as its 
name, description, and associated vulnerabilities. This structured data format made it easier to process and analyze the 
information, compared to the web scraping approach.

For each vendor extracted from the Home Assistant device list, we queried this endpoint and saved the results in a JSON
file with the following structure :

| Field | Description                                      |
|-------|--------------------------------------------------|
| `vendor` | The vendor name as retrieved from Home Assistant |
| `products` | A list of products associated with the vendor, as retrieved from the CIRCL API |

This approach confirmed that the vulnerability databases uses its own standardized naming convention for vendors and
products, which differs from the naming convention used in Home Assistant. This can make it difficult to accurately 
match devices from Home Assistant with the corresponding entries in the CIRCL database, and may require additional 
processing or manual intervention to ensure accurate vulnerability information is retrieved.

#### Limitations & observations
The endpoint requires the exact vendor name as referenced in the CIRCL database, which may differ from the vendor name 
retrieved from Home Assistant. This can lead to difficulties in matching devices and retrieving relevant vulnerability
information. Additionally, there is no fuzzy search available in API, meaning that any mismatch between the vendor name
in Home Assistant and the one in the database results in an empty response. Furthermore, the API may have rate limits or
other restrictions that could impact the performance of our application if we need to retrieve vulnerability information 
for a large number of devices.

#### Results
The script successfully retrieved the list of products associated with each vendor present in the Home Assistant device
list, using the CIRCL Vulnerability Lookup API. The results were saved in the `ha_products_by_vendor_example` JSON file.

---

## References
- [Home Assistant WebSocket API](https://developers.home-assistant.io/docs/api/websocket/)
- [CIRCL Vulnerability Lookup](https://vulnerability.circl.lu/)

<p align="right">(<a href="#About-the-project">back to top</a>)</p>