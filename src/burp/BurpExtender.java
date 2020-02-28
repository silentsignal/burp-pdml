package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.*;
import javax.xml.namespace.QName;
import javax.xml.xpath.*;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

public class BurpExtender implements IBurpExtender, ITab, ListSelectionListener, ActionListener {
	private final static String XPATH_REQUEST_METHODS = "//field[@name='http.request.method']";
	private final static String XPATH_REQUEST_LINES = "field[@name='http.request.line']/@value";
	private final static String XPATH_REQUEST_URI = "field[@name='http.request.full_uri']/@show";
	private final static String XPATH_REQUEST_TS = "../proto[@name='geninfo']/field[@name='timestamp']/@show";
	private final static String XPATH_REQUEST_ID = "../proto[@name='geninfo']/field[@name='num']/@show";
	private final static String XPATH_REQUEST_RESP = "field[@name='http.response_in']/@show";
	private final static String XPATH_RESPONSE_BY_ID = "//proto[@name='geninfo']/field[@name='num' and @show=%d]/../../proto[@name='http']//field[@name='http.response.code']";
	private final static String XPATH_RESPONSE_LINES = "field[@name='http.response.line']/@value";
	private final static String XPATH_FILE_DATA = "field[@name='http.file_data']/@value";
	// TODO use table instead of list
	private final DefaultListModel<Entry> model = new DefaultListModel<>();
	private final JList<Entry> list = new JList<>(model);
	private final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); 
	private final JTabbedPane tabs = new JTabbedPane();
	private IMessageEditor requestViewer, responseViewer;
	private final EntryProxy proxy = new EntryProxy();
	private IBurpExtenderCallbacks callbacks;

	private static class Entry implements IHttpService {
		public final byte[] request, response;
		private final String host, protocol, verb, timestamp;
		private final int port, id;
		private final URL url;
		private final short status;

		public Entry(byte[] request, byte[] response, String verb, URL url,
				String timestamp, short status, int id) {
			this.request = request;
			this.response = response;
			this.verb = verb;
			this.url = url;
			int port = url.getPort();
			if (port == -1) {
				port = url.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
			}
			this.port = port;
			this.host = url.getHost();
			this.protocol = url.getProtocol();
			this.timestamp = timestamp;
			this.status = status;
			this.id = id;
		}

		public String toString() {
			return String.format("(%d) %s | %s %s (%d)", id, timestamp, verb, url, status);
		}

		public String getHost() { return host; }
		public int getPort() { return port; }
		public String getProtocol() { return protocol; }
	}

	private static class EntryProxy implements IMessageEditorController {
		private Entry target;
		private static final byte[] EMPTY_BYTE_ARRAY = {};

		public void setTarget(Entry target) { this.target = target; }
		public IHttpService getHttpService() { return target; }
		public byte[] getRequest() { return target == null ? EMPTY_BYTE_ARRAY : target.request; }
		public byte[] getResponse() { return target == null ? EMPTY_BYTE_ARRAY : target.response; }
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("PDML importer");
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.addListSelectionListener(this);
		requestViewer = callbacks.createMessageEditor(proxy, false);
		responseViewer = callbacks.createMessageEditor(proxy, false);
		tabs.addTab("Request", requestViewer.getComponent());
		tabs.addTab("Response", responseViewer.getComponent());
		JPanel topPart = new JPanel(new BorderLayout());
		JButton btn = new JButton("Import requests from PDML file");
		btn.addActionListener(this);
		topPart.add(btn, BorderLayout.PAGE_START);
		topPart.add(new JScrollPane(list), BorderLayout.CENTER);
		splitPane.setTopComponent(topPart);
		splitPane.setBottomComponent(tabs);
		callbacks.addSuiteTab(this);
		this.callbacks = callbacks;
	}

	@Override public String getTabCaption() { return "PDML"; }
	@Override public Component getUiComponent() { return splitPane; }

	@Override
	public void valueChanged(ListSelectionEvent e) {
		final Entry entry = model.get(list.getSelectedIndex());
		proxy.setTarget(entry);
		requestViewer.setMessage(entry.request, true);
		responseViewer.setMessage(entry.response, false);
	}

	@Override
	public void actionPerformed(ActionEvent evt) {
		final JFileChooser fileChooser = new JFileChooser();
		if (fileChooser.showOpenDialog(list) == JFileChooser.APPROVE_OPTION) {
			try {
				fillModelFromPDML(fileChooser.getSelectedFile().getPath());
			} catch (Exception e) {
				e.printStackTrace(new PrintStream(callbacks.getStderr()));
			}
		}
	}

	private void fillModelFromPDML(final String pdmlFile) throws IOException, ParserConfigurationException, SAXException, XPathExpressionException { // TODO remove static
		DocumentBuilderFactory factory =
			DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc;
		try (InputStream s = new FileInputStream(pdmlFile)) {
			doc = builder.parse(s);
		}
		XPath xPath =  XPathFactory.newInstance().newXPath();
		
		NodeList methods = (NodeList) xPath.compile(XPATH_REQUEST_METHODS).evaluate(doc, XPathConstants.NODESET);

		XPathExpression reqLines = xPath.compile(XPATH_REQUEST_LINES);
		XPathExpression reqUri = xPath.compile(XPATH_REQUEST_URI);
		XPathExpression reqTimestamp = xPath.compile(XPATH_REQUEST_TS);
		XPathExpression reqId = xPath.compile(XPATH_REQUEST_ID);
		XPathExpression reqRespIn = xPath.compile(XPATH_REQUEST_RESP);
		XPathExpression respLines = xPath.compile(XPATH_RESPONSE_LINES);
		XPathExpression fileData = xPath.compile(XPATH_FILE_DATA);

		for (int i = 0; i < methods.getLength(); i++) {
			StringBuilder sb = new StringBuilder();
			Node method = methods.item(i);
			String verb = method.getAttributes().getNamedItem("show").getNodeValue();
			Node firstField = method.getParentNode();
			Node topLevel = firstField.getParentNode();
			sb.append(firstField.getAttributes().getNamedItem("value").getNodeValue());
			NodeList lines = (NodeList) reqLines.evaluate(topLevel, XPathConstants.NODESET);
			for (int j = 0; j < lines.getLength(); j++) {
				sb.append(lines.item(j).getNodeValue());
			}
			String fd = (String) fileData.evaluate(topLevel, XPathConstants.STRING);
			sb.append("0d0a");
			if (fd != null) {
				sb.append(fd);
			}
			byte[] req = decodeHex(sb);
			sb.setLength(0);
			URL url = new URL((String) reqUri.evaluate(topLevel, XPathConstants.STRING));
			String ts = (String) reqTimestamp.evaluate(topLevel, XPathConstants.STRING);
			int id = Integer.valueOf((String)reqId.evaluate(topLevel, XPathConstants.STRING));

			XPathExpression respById = xPath.compile(String.format(XPATH_RESPONSE_BY_ID,
						Integer.valueOf((String)reqRespIn.evaluate(topLevel, XPathConstants.STRING))));
			Node responseCode = (Node) respById.evaluate(doc, XPathConstants.NODE);
			short status = Short.parseShort(responseCode.getAttributes().getNamedItem("show").getNodeValue());
			firstField = responseCode.getParentNode();
			sb.append(firstField.getAttributes().getNamedItem("value").getNodeValue());
			topLevel = firstField.getParentNode();
			lines = (NodeList) respLines.evaluate(topLevel, XPathConstants.NODESET);
			for (int j = 0; j < lines.getLength(); j++) {
				sb.append(lines.item(j).getNodeValue());
			}
			fd = (String) fileData.evaluate(topLevel, XPathConstants.STRING);
			sb.append("0d0a");
			if (fd != null) {
				sb.append(fd);
			}
			byte[] resp = decodeHex(sb);
			model.addElement(new Entry(req, resp, verb, url, ts, status, id));
		}
	}

	private static byte[] decodeHex(StringBuilder sb) {
		final int digits = sb.length();
		final int bytes = digits / 2;
		final byte[] result = new byte[bytes];
		for (int i = 0; i < bytes; i++) {
			result[i] = (byte)Short.parseShort(sb.substring(i * 2, (i + 1) * 2), 16);
		}
		return result;
	}
}
