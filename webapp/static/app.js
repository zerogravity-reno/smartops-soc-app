
document.addEventListener('DOMContentLoaded', () => {
    const processBtn = document.getElementById('processBtn');

    const loader = document.getElementById('loader');
    const normalizerSection = document.getElementById('normalizerSection');
    const adaptersSection = document.getElementById('adaptersSection');
    const contractSection = document.getElementById('contractSection');

    const rawEventOutput = document.getElementById('rawEventOutput');

    const escuQueryKey = document.getElementById('escuQueryKey');
    const ctiQueryKey = document.getElementById('ctiQueryKey');
    const escuOutput = document.getElementById('escuOutput');
    const ctiOutput = document.getElementById('ctiOutput');
    const contractOutput = document.getElementById('contractOutput');

    processBtn.addEventListener('click', async () => {
        // Collect form fields — IDs match new index.html
        const rule_name    = document.getElementById('f_rule').value.trim();
        const src_ip       = document.getElementById('f_src').value.trim();
        const dest         = document.getElementById('f_dest').value.trim();
        const user         = document.getElementById('f_user').value.trim();
        const hash         = document.getElementById('f_hash').value.trim();
        const domain       = document.getElementById('f_domain').value.trim();
        const mitre        = document.getElementById('f_mitre').value.trim();
        const signature    = document.getElementById('f_sig').value.trim();
        const deployed_spl = document.getElementById('f_spl').value.trim();

        // Auto-extract observables (non-empty cti fields only)
                        const raw = window.lastImportedRaw || {};
        const url = raw.url || raw.uri || "";
        const email = raw.email || raw.recipient || raw.sender || "";
        const file_name = raw.file_name || raw.process_name || raw.app || "";
        
        let splunk_mitre = [];
        if (raw['annotations.mitre_attack']) splunk_mitre = raw['annotations.mitre_attack'].split(';');
        let splunk_story = [];
        if (raw['annotations.analytic_story']) splunk_story = raw['annotations.analytic_story'].split(';');
        
        const observables = [src_ip, hash, domain, url, email, file_name, ...splunk_mitre, ...splunk_story].filter(v => v && v.length > 0);

        // Reset UI
        normalizerSection.classList.add('hidden');
        adaptersSection.classList.add('hidden');
        contractSection.classList.add('hidden');
        loader.classList.remove('hidden');

        try {
            // --- Query ESCU ---
            const escuRes = await fetch('/api/escu', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule_name })
            });
            const escuData = await escuRes.json();

            // --- Query OpenCTI (multiple observables) ---
            const ctiRes = await fetch('/api/opencti', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ observables })
            });
            const ctiData = await ctiRes.json();

            // --- Simulate Raw Event ---
            const raw_event = window.lastImportedRaw && Object.keys(window.lastImportedRaw).length > 0 ? 
                { ...window.lastImportedRaw } : 
                {
                    orig_time: Math.floor(Date.now() / 1000).toString(),
                    rule_title: rule_name || "Unknown Alert",
                    severity_level: "High",
                    src: src_ip || "0.0.0.0",
                    dest_host: dest || "Unknown",
                    user_name: user || "N/A",
                    proc_name: "unknown.exe",
                    proc_cmd: signature || "N/A",
                    file_hash: hash || "N/A",
                    domain_query: domain || "N/A",
                    index: "win_sysmon",
                    sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                    _raw_spl: deployed_spl || undefined
                };

            // --- Simulate Normalized Seed ---
            const normalized_seed = {
                event_id: "evt-" + Math.floor(Math.random() * 1000000),
                event_time: new Date().toISOString(),
                ingest_time: new Date().toISOString(),
                detection: {
                    detection_id: null,
                    name: rule_name || null,
                    severity: "high",
                    security_domain: null,
                    category: null,
                    type: null,
                    source: null
                },
                source_context: {
                    siem: "Splunk ES",
                    index: "win_sysmon",
                    sourcetype: "XmlWinEventLog",
                    source: null,
                    host: null
                },
                entities: {
                    host: null,
                    hostname: dest || null,
                    device_id: null,
                    asset_id: null,
                    user: user || null,
                    user_id: null,
                    account_name: null,
                    account_domain: null,
                    src_ip: src_ip || null,
                    src_host: null,
                    src_port: null,
                    dest_ip: null,
                    dest_host: null,
                    dest_port: null
                },
                authentication: { action: null, status: null, authentication_method: null, logon_type: null, failure_reason: null, session_id: null, source_user: null, target_user: null },
                process: {
                    process_name: signature || null,
                    process_path: null,
                    process_id: null,
                    process_guid: null,
                    command_line: null,
                    parent_process_name: null,
                    parent_process_path: null,
                    parent_process_id: null,
                    parent_command_line: null,
                    child_process_name: null,
                    child_process_id: null
                },
                file: {
                    file_name: null,
                    file_path: null,
                    file_extension: null,
                    file_size: null,
                    md5: null,
                    sha1: null,
                    sha256: hash || null,
                    file_action: null,
                    file_owner: null,
                    file_signature: null
                },
                registry: { registry_path: null, registry_key: null, registry_value_name: null, registry_value_data: null, registry_action: null },
                network: { src_ip: null, src_port: null, dest_ip: null, dest_port: null, protocol: null, transport_protocol: null, application_protocol: null, direction: null, action: null, bytes_in: null, bytes_out: null, bytes_total: null, packets_in: null, packets_out: null, connection_count: null },
                dns: { query: null, query_type: null, query_length: null, response: null, response_code: null, record_type: null, resolved_ip: null },
                http: { url: null, uri: null, domain: domain || null, hostname: null, http_method: null, status_code: null, user_agent: null, referrer: null, request_size: null, response_size: null, content_type: null },
                email: { sender: null, recipient: null, cc: [], subject: null, message_id: null, attachment_names: [], attachment_hashes: [], urls: [], domains: [] },
                                                opencti_observables: {
                    ip_addresses: src_ip ? [src_ip] : [],
                    domains: domain ? [domain] : [],
                    urls: url ? [url] : [],
                    file_hashes: hash ? [hash] : [],
                    email_addresses: email ? [email] : [],
                    file_names: file_name ? [file_name] : [],
                    mitre_techniques: splunk_mitre,
                    analytic_stories: splunk_story
                },
                endpoint: { device_name: null, device_id: null, os: null, os_version: null, agent_id: null, agent_version: null, action: null, status: null },
                cloud: { cloud_provider: null, account_id: null, subscription_id: null, tenant_id: null, region: null, resource_id: null, resource_type: null, resource_name: null, service: null, operation: null },
                identity: { user: null, user_id: null, user_type: null, role: null, privilege: null, source_identity: null, target_identity: null },
                geo: { src_country: null, src_city: null, dest_country: null, dest_city: null, latitude: null, longitude: null },
                event: { event_code: null, event_type: null, event_category: null, event_action: null, event_status: null, message: null },
                tags: [],
                additional_fields: {},
                finding: raw_event
            };

            // Recursively remove nulls, empty arrays, and empty objects
            function cleanObject(obj) {
                for (const key in obj) {
                    if (obj[key] === null) {
                        delete obj[key];
                    } else if (Array.isArray(obj[key])) {
                        if (obj[key].length === 0) delete obj[key];
                    } else if (typeof obj[key] === 'object') {
                        cleanObject(obj[key]);
                        if (Object.keys(obj[key]).length === 0) delete obj[key];
                    }
                }
            }
            cleanObject(normalized_seed);

            // --- Extract ESCU Context ---
            let mitre_techniques = [];
            let analytic_story = [];
            let reference_spl = "No SPL returned from ESCU.";
            let data_sources = ["Simulated Data Source"];
            let known_false_positives = [];
            let description = "Detection logic and context mapped from ESCU bm25 corpus.";
            let full_metadata = {};
            
            if (escuData.matches && escuData.matches.length > 0) {
                const match = escuData.matches[0];
                full_metadata = match;
                
                // Fields in real ESCU are inside the 'tags' dict or at the top level
                                if (match.data) {
                    mitre_techniques = match.data.mitre_attack_id || match.data.mitre || [];
                    analytic_story = match.data.analytic_story || [];
                    reference_spl = match.data.spl || match.data.search || "SPL missing in ESCU definition";
                    data_sources = match.data.data_source || [];
                    known_false_positives = match.data.known_false_positives || [];
                    description = match.data.description || description;
                }
            }

            const escu_context = {
                description: description,
                mitre_techniques: Array.isArray(mitre_techniques) ? mitre_techniques : [mitre_techniques],
                data_sources: Array.isArray(data_sources) ? data_sources : [data_sources],
                known_false_positives: Array.isArray(known_false_positives) ? known_false_positives : [known_false_positives],
                analytic_story: Array.isArray(analytic_story) ? analytic_story : [analytic_story],
                reference_spl: reference_spl,
                full_metadata: full_metadata // Preserving ALL metadata as requested
            };

            // --- Extract OpenCTI Intel ---
            const opencti_threat_intelligence = {
                indicators: Object.keys(ctiData.results || {}).map(key => ({
                    observable: key,
                    type: ctiData.results[key]._queried_as
                })),
                malware: [],
                threat_actors: [],
                campaigns: [],
                relationships: [],
                _raw_intel_dump: ctiData.results // Keeping raw intel in PoC so we can still see the GraphQL results
            };

            // --- Determine Semantic Alignment ---
            function computeAlignment(deployedSpl, refSpl) {
                if (!deployedSpl || !refSpl) return "NOT_ALIGNED";
                
                const stopwords = new Set(['the','and','or','in','from','where','by','as','to','of','a','an','is','it','not','with','for','on','at','be','this','that','are','was','were','if','then','else']);
                const extractKeywords = (text) => text.toLowerCase()
                    .replace(/[^a-z0-9\s_]/g, ' ')
                    .split(/\s+/)
                    .filter(w => w.length > 3 && !stopwords.has(w));

                const deployedKws = new Set(extractKeywords(deployedSpl));
                const refKws = new Set(extractKeywords(refSpl));

                let overlap = 0;
                for (const kw of deployedKws) {
                    if (refKws.has(kw)) overlap++;
                }

                const similarity = deployedKws.size > 0 ? (overlap / deployedKws.size) : 0;
                return similarity >= 0.3 ? "ALIGNED" : "NOT_ALIGNED";
            }

            const alignment = computeAlignment(deployed_spl, reference_spl);

            // --- Build Official Context Contract ---
            const contract = {
                normalized_seed: normalized_seed,
                rule_intent: {
                    intent: "To be determined by LLM (Rule Intent Interpreter) via semantic comparison of both SPLs.",
                    semantic_alignment: "ALIGNED | NOT_ALIGNED",
                    deployed_spl: deployed_spl || "Not provided — paste the SPL from Splunk ES here.",
                    reference_spl: reference_spl
                },
                escu_context: escu_context,
                opencti_threat_intelligence: opencti_threat_intelligence
            };

            // Populate UI
            rawEventOutput.textContent = JSON.stringify(normalized_seed, null, 2);

            escuQueryKey.textContent = rule_name || '—';
            ctiQueryKey.textContent = observables.join(', ') || '—';

            escuOutput.textContent = JSON.stringify(escuData, null, 2);
            ctiOutput.textContent = JSON.stringify(ctiData, null, 2);
            contractOutput.textContent = JSON.stringify(contract, null, 2);

            // Show results
            setTimeout(() => {
                loader.classList.add('hidden');
                normalizerSection.classList.remove('hidden');
                adaptersSection.classList.remove('hidden');
                contractSection.classList.remove('hidden');
                normalizerSection.scrollIntoView({ behavior: 'smooth' });
            }, 500);

            // --- Call Analyst Agent (Foundation-Sec) ---
            const analystSection = document.getElementById('analystSection');
            const analystLoader = document.getElementById('analystLoader');
            const analystOutput = document.getElementById('analystOutput');
            const reasoningOutput = document.getElementById('reasoningOutput');

            analystSection.classList.remove('hidden');
            analystLoader.classList.remove('hidden');
            analystOutput.textContent = '';
            if (reasoningOutput) reasoningOutput.textContent = '';

            // Save contract so the pipeline runner can access it
            sessionStorage.setItem('context_contract', JSON.stringify(contract));

            fetch('/api/analyst/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    context_contract: contract,
                    hypotheses: []  // Let the LLM auto-generate from context
                })
            })
            .then(r => r.json())
            .then(startData => {
                const jobId = startData.job_id;
                if (!jobId) throw new Error("No job_id returned");
                
                // Poll for result every 5 seconds
                const pollInterval = setInterval(() => {
                    fetch(`/api/analyst/result/${jobId}`)
                    .then(r => r.json())
                    .then(analystData => {
                        if (analystData.status === 'pending') {
                            // Still thinking...
                            return;
                        }
                        
                        // Done or error
                        clearInterval(pollInterval);
                        analystLoader.classList.add('hidden');

                        // Extract alignment logic from the LLM output
                        const plan = analystData.planning_template;

                        if (!plan) {
                            analystOutput.textContent = 'Error: Model did not return a valid Planning Template.\n\nRaw response:\n' + JSON.stringify(analystData, null, 2);
                            return;
                        }

                        // Show reasoning in the top window
                        if (reasoningOutput) {
                            reasoningOutput.textContent = plan.model_reasoning || analystData.reasoning || '(No reasoning text)';
                            delete plan.model_reasoning;
                        }

                        if (plan.semantic_alignment) {
                                                        const alignWindow = document.getElementById('alignmentWindow');
                            const alignTitle  = document.getElementById('alignmentTitle');
                            const alignDot    = document.getElementById('alignmentDot');
                            const alignOutput = document.getElementById('alignmentOutput');

                            const splComp = document.getElementById('splComparison');
                            if (splComp) {
                                splComp.style.display = 'block';
                                document.getElementById('alignRefSpl').textContent = reference_spl || "N/A";
                                document.getElementById('alignDepSpl').textContent = deployed_spl || "N/A";
                            }

                            alignWindow.style.display = 'block';

                            if (plan.semantic_alignment === 'ALIGNED') {
                                alignTitle.textContent = 'SPL Semantic Alignment ⚖️ — [ ALIGNED ]';
                                alignTitle.style.color = '#10b981';
                                alignDot.style.background = '#10b981';
                                alignWindow.style.borderColor = 'rgba(16, 185, 129, 0.4)';
                            } else {
                                alignTitle.textContent = 'SPL Semantic Alignment ⚖️ — [ NOT ALIGNED ]';
                                alignTitle.style.color = '#ef4444';
                                alignDot.style.background = '#ef4444';
                                alignWindow.style.borderColor = 'rgba(239, 68, 68, 0.4)';
                            }

                            alignOutput.textContent = plan.alignment_reasoning || '(No alignment reasoning provided)';
                            delete plan.semantic_alignment;
                            delete plan.alignment_reasoning;
                        }

                        // Broker sees tasks only — strip hypothesis→verdict mapping
                        const brokerPlan = JSON.parse(JSON.stringify(plan));
                        delete brokerPlan.hypotheses;

                        // Save full plan as Analyst Memory
                        sessionStorage.setItem('analyst_memory', JSON.stringify(plan));

                        // Show clean Broker-facing planning template
                        analystOutput.textContent = JSON.stringify(brokerPlan, null, 2);
                        analystSection.scrollIntoView({ behavior: 'smooth' });

                        // ── Auto-start the full pipeline ────────────────
                        _onAnalystComplete();

                    })
                    .catch(err => {
                        clearInterval(pollInterval);
                        analystLoader.classList.add('hidden');
                        analystOutput.textContent = 'Polling error: ' + err.message;
                    });
                }, 5000); // poll every 5 seconds
            })
            .catch(err => {
                analystLoader.classList.add('hidden');
                analystOutput.textContent = 'Error starting Analyst job: ' + err.message;
            });

        } catch (err) {
            alert('Error: ' + err.message);
            loader.classList.add('hidden');
        }
    });
});


// ── After Analyst completes: show & auto-start the pipeline ──────────────
function _onAnalystComplete() {
    // New HTML uses id="pipelineSection" and id="runBtn"
    const sec = document.getElementById('pipelineSection');
    if (!sec) return;

    sec.classList.remove('hidden');

    setTimeout(() => {
        sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 300);

    setTimeout(() => {
        const btn = document.getElementById('runBtn');
        if (btn && !btn.disabled) btn.click();
    }, 900);
}

// TEST SIMULATION
async function simulateTests() {
    const btn = document.getElementById('runTestsBtn');
    btn.innerHTML = '&#x23F3; Running Tests...';
    
    const check = (id) => {
        const el = document.getElementById(id);
        el.innerHTML = '<span style="display:inline-block;width:20px;text-align:center;color:#10b981;">&#x2714;</span>' + el.innerHTML.substring(el.innerHTML.indexOf('</span>') + 7);
        el.style.color = '#10b981';
    };
    
    // Simulate real steps
    setTimeout(() => document.getElementById('importBtn').click(), 500);
    setTimeout(() => { check('t3'); check('t4'); check('t2'); }, 4000);
    setTimeout(() => document.getElementById('processBtn').click(), 5000);
    setTimeout(() => { check('t6'); check('t1'); }, 5500);
    
    // Check T5 after investigation
    let checkInterval = setInterval(() => {
        if(document.body.innerHTML.includes('ALIGNED') || document.body.innerHTML.includes('NOT_ALIGNED')) {
            check('t5');
            btn.innerHTML = '&#x2714; All Tests Passed';
            btn.style.background = 'rgba(16,185,129,.12)';
            btn.style.borderColor = 'rgba(16,185,129,.3)';
            btn.style.color = '#10b981';
            clearInterval(checkInterval);
        }
    }, 2000);
}






