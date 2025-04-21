/**
 * ZAP MCP Server
 * Custom ZAP server with GitHub integration for security scanning workflows
 */

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const cron = require('node-cron');
const multer = require('multer');
const { Octokit } = require('@octokit/rest');
const crypto = require('crypto');

// Load configuration
const config = require('./config.json');

// Configure logger
const logger = winston.createLogger({
  level: config.logging.level || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ 
      filename: config.logging.file || 'server.log',
      dirname: path.dirname(config.logging.file || 'server.log')
    })
  ]
});

// Create upload directory for temporary files
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Create reports directory
if (!fs.existsSync(config.reports.outputDir)) {
  fs.mkdirSync(config.reports.outputDir, { recursive: true });
}

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Active scans in progress
const activeScans = new Map();

// ZAP API base URL
const zapApiUrl = `http://${config.zap.host}:${config.zap.port}/JSON`;

/**
 * Helper function to make requests to ZAP API
 */
async function zapRequest(endpoint, params = {}) {
  const requestParams = {
    ...params,
    apikey: config.zap.apiKey
  };
  
  try {
    const response = await axios.get(`${zapApiUrl}/${endpoint}`, { params: requestParams });
    return response.data;
  } catch (error) {
    logger.error(`ZAP API request failed: ${error.message}`, { endpoint, params });
    throw error;
  }
}

/**
 * Health check endpoint
 */
app.get('/health', async (req, res) => {
  try {
    // Check ZAP connection
    const zapVersion = await zapRequest('core/view/version');
    
    return res.json({
      status: 'ok',
      zap: {
        connected: true,
        version: zapVersion.version
      },
      server: {
        uptime: process.uptime(),
        activeScanCount: activeScans.size
      }
    });
  } catch (error) {
    return res.status(500).json({
      status: 'error',
      message: 'ZAP connection failed',
      error: error.message
    });
  }
});

/**
 * Start a new scan
 */
app.post('/scan', async (req, res) => {
  try {
    const { target, scan_type = 'baseline', options = {} } = req.body;
    
    if (!target) {
      return res.status(400).json({
        status: 'error',
        message: 'Target URL is required'
      });
    }
    
    // Validate scan type
    const scanConfig = config.github.scanTypes[scan_type];
    if (!scanConfig) {
      return res.status(400).json({
        status: 'error',
        message: `Invalid scan type: ${scan_type}`
      });
    }
    
    // Generate scan ID
    const scanId = uuidv4();
    
    // Combine default options with custom options
    const scanOptions = {
      ...scanConfig.options,
      ...options
    };
    
    // Start scan asynchronously
    startScan(scanId, target, scanOptions);
    
    // Add to active scans
    activeScans.set(scanId, {
      id: scanId,
      target,
      scan_type,
      options: scanOptions,
      status: 'starting',
      start_time: new Date().toISOString(),
      progress: 0
    });
    
    return res.status(202).json({
      status: 'accepted',
      message: 'Scan started',
      scan_id: scanId
    });
  } catch (error) {
    logger.error(`Error starting scan: ${error.message}`);
    return res.status(500).json({
      status: 'error',
      message: 'Failed to start scan',
      error: error.message
    });
  }
});

/**
 * Get scan status
 */
app.get('/scan/:scanId/status', (req, res) => {
  const { scanId } = req.params;
  
  if (!activeScans.has(scanId)) {
    return res.status(404).json({
      status: 'error',
      message: 'Scan not found'
    });
  }
  
  return res.json({
    status: 'ok',
    scan: activeScans.get(scanId)
  });
});

/**
 * Get scan results
 */
app.get('/scan/:scanId/results', (req, res) => {
  const { scanId } = req.params;
  
  if (!activeScans.has(scanId)) {
    return res.status(404).json({
      status: 'error',
      message: 'Scan not found'
    });
  }
  
  const scan = activeScans.get(scanId);
  
  if (scan.status !== 'completed') {
    return res.status(400).json({
      status: 'error',
      message: `Scan is not completed (current status: ${scan.status})`
    });
  }
  
  return res.json({
    status: 'ok',
    scan,
    results: scan.results
  });
});

/**
 * Start a new scan with the given options
 */
async function startScan(scanId, target, options) {
  try {
    logger.info(`Starting scan: ${scanId} for target: ${target}`);
    
    // Update scan status
    updateScanStatus(scanId, 'preparing', 0);
    
    // Initialize ZAP session
    await zapRequest('core/action/newSession');
    
    // Set context
    const contextId = 1;
    const contextName = `scan-${scanId}`;
    await zapRequest('context/action/newContext', { contextName });
    
    // Include target in context
    await zapRequest('context/action/includeInContext', { 
      contextName, 
      regex: target + '.*' 
    });
    
    // Start spider if enabled
    updateScanStatus(scanId, 'spider', 5);
    if (options.spider) {
      await zapRequest('spider/action/scan', { url: target });
      
      // Wait for spider to complete
      let spiderProgress = 0;
      while (spiderProgress < 100) {
        const spiderStatusResponse = await zapRequest('spider/view/status');
        spiderProgress = parseInt(spiderStatusResponse.status);
        updateScanStatus(scanId, 'spider', 5 + Math.floor(spiderProgress * 0.25));
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    
    // Start AJAX Spider if enabled
    updateScanStatus(scanId, 'ajax', 30);
    if (options.ajax) {
      await zapRequest('ajaxSpider/action/scan', { url: target });
      
      // Wait for AJAX spider to complete
      let ajaxSpiderRunning = true;
      while (ajaxSpiderRunning) {
        const ajaxStatusResponse = await zapRequest('ajaxSpider/view/status');
        ajaxSpiderRunning = ajaxStatusResponse.running === 'true';
        updateScanStatus(scanId, 'ajax', 30 + (ajaxSpiderRunning ? 0 : 20));
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
    
    // Start active scan if enabled
    updateScanStatus(scanId, 'active', 50);
    if (options.active) {
      await zapRequest('ascan/action/scan', { 
        url: target,
        contextId
      });
      
      // Wait for active scan to complete
      let activeScanProgress = 0;
      while (activeScanProgress < 100) {
        const activeScanStatusResponse = await zapRequest('ascan/view/status');
        activeScanProgress = parseInt(activeScanStatusResponse.status);
        updateScanStatus(scanId, 'active', 50 + Math.floor(activeScanProgress * 0.4));
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
    
    // Fetch alerts
    updateScanStatus(scanId, 'gathering_results', 90);
    const alertsResponse = await zapRequest('core/view/alerts', { 
      baseurl: target
    });
    
    // Generate reports
    updateScanStatus(scanId, 'generating_reports', 95);
    const reports = await generateReports(scanId, target);
    
    // Complete scan
    const results = {
      alerts: alertsResponse.alerts,
      summary: summarizeAlerts(alertsResponse.alerts),
      reports
    };
    
    updateScanStatus(scanId, 'completed', 100, results);
    logger.info(`Scan completed: ${scanId}`);
    
  } catch (error) {
    logger.error(`Scan failed: ${scanId}, error: ${error.message}`);
    updateScanStatus(scanId, 'failed', 0, null, error.message);
  }
}

/**
 * Update scan status in the active scans map
 */
function updateScanStatus(scanId, status, progress, results = null, error = null) {
  if (!activeScans.has(scanId)) {
    return;
  }
  
  const scan = activeScans.get(scanId);
  
  activeScans.set(scanId, {
    ...scan,
    status,
    progress,
    update_time: new Date().toISOString(),
    results: results || scan.results,
    error: error || scan.error
  });
  
  logger.debug(`Scan ${scanId} status updated: ${status}, progress: ${progress}%`);
}

/**
 * Summarize alerts by risk level
 */
function summarizeAlerts(alerts) {
  const summary = {
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    total: alerts.length
  };
  
  alerts.forEach(alert => {
    const risk = alert.risk.toLowerCase();
    if (risk === 'high') summary.high++;
    else if (risk === 'medium') summary.medium++;
    else if (risk === 'low') summary.low++;
    else summary.informational++;
  });
  
  return summary;
}

/**
 * Generate reports in different formats
 */
async function generateReports(scanId, target) {
  const reportTypes = config.reports.formats || ['html', 'xml', 'json'];
  const reports = {};
  
  for (const format of reportTypes) {
    try {
      const reportFilename = `${scanId}-${format}.${format}`;
      const reportPath = path.join(config.reports.outputDir, reportFilename);
      
      await zapRequest('reports/action/generate', {
        title: `Security Scan Report - ${target}`,
        template: format,
        reportFileName: reportPath,
        description: `Security scan report for ${target}`
      });
      
      reports[format] = reportFilename;
      logger.debug(`Generated ${format} report for scan ${scanId}`);
    } catch (error) {
      logger.error(`Failed to generate ${format} report for scan ${scanId}: ${error.message}`);
    }
  }
  
  return reports;
}

/**
 * GitHub webhook endpoint
 */
app.post('/github/webhook', async (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'];
  
  // Verify webhook signature
  if (config.github.webhookSecret) {
    const hmac = crypto.createHmac('sha256', config.github.webhookSecret);
    const calculatedSignature = 'sha256=' + hmac.update(JSON.stringify(req.body)).digest('hex');
    
    if (signature !== calculatedSignature) {
      logger.warn('Invalid GitHub webhook signature');
      return res.status(401).json({ status: 'error', message: 'Invalid signature' });
    }
  }
  
  // Process webhook events
  try {
    if (event === 'push') {
      // Handle push event (e.g., scan on push to main branch)
      const { repository, ref } = req.body;
      
      if (ref === 'refs/heads/main' || ref === 'refs/heads/master') {
        logger.info(`Push to main branch detected for ${repository.full_name}`);
        // Start a scan for the repository
        // Implementation would depend on your requirements
      }
    } else if (event === 'pull_request') {
      // Handle pull request events
      const { action, pull_request, repository } = req.body;
      
      if (action === 'opened' || action === 'synchronize') {
        logger.info(`Pull request ${action} detected for ${repository.full_name}#${pull_request.number}`);
        // Start a scan for the pull request
        // Implementation would depend on your requirements
      }
    }
    
    return res.json({ status: 'ok', message: 'Webhook received' });
  } catch (error) {
    logger.error(`Error processing GitHub webhook: ${error.message}`);
    return res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

/**
 * Periodic cleanup of old scans
 */
cron.schedule('0 * * * *', () => {
  logger.info('Running scheduled cleanup of old scans');
  const now = new Date();
  
  for (const [scanId, scan] of activeScans.entries()) {
    // Remove completed scans older than 24 hours
    if (scan.status === 'completed' || scan.status === 'failed') {
      const scanTime = new Date(scan.update_time || scan.start_time);
      const hoursDiff = (now - scanTime) / (1000 * 60 * 60);
      
      if (hoursDiff > 24) {
        logger.debug(`Removing old scan: ${scanId}`);
        activeScans.delete(scanId);
      }
    }
  }
});

// Start server
const PORT = config.server.port || 8090;
const HOST = config.server.host || '0.0.0.0';

app.listen(PORT, HOST, () => {
  logger.info(`ZAP MCP Server started on ${HOST}:${PORT}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received, shutting down');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received, shutting down');
  process.exit(0);
});
