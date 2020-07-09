package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.xml.parsers.*;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.*;

public class BurpExtender extends DefaultHandler implements IBurpExtender, ITab, ListSelectionListener, ActionListener {
	// TODO use table instead of list
	private final DefaultListModel<Entry> model = new DefaultListModel<>();
	private final JList<Entry> list = new JList<>(model);
	private final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); 
	private final JTabbedPane tabs = new JTabbedPane();
	private IMessageEditor requestViewer, responseViewer;
	private final EntryProxy proxy = new EntryProxy();
	private IBurpExtenderCallbacks callbacks;

	private static class Request {
		public final byte[] request;
		private final String host, protocol, verb, timestamp;
		private final int port, id;
		private final URL url;

		public Request(byte[] request, String verb, URL url,
				String timestamp, int id) {
			this.request = request;
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
			this.id = id;
		}

		public Entry complete(byte[] response, short status) {
			return new Entry(request, response, verb, url, timestamp, status, id);
		}
	}

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
				fillModelFromPDML(fileChooser.getSelectedFile());
			} catch (Exception e) {
				e.printStackTrace(new PrintStream(callbacks.getStderr()));
			}
		}
	}

	private Map<Integer, Request> requests = new HashMap<Integer, Request>();
	private int frameNumber;
	private Integer responseIn;
	private String protoName, timestamp, method;
	private StringBuilder sb = null;
	private URL url;
	private short status;

	@Override
	public void startDocument() throws SAXException {
		sb = new StringBuilder();
	}

	@Override
	public void endDocument() throws SAXException {
		requests.clear();
		sb = null; // let the GC free the buffer
	}

	@Override
	public void startElement(String namespaceURI, String localName,
			String qName, Attributes atts) throws SAXException {
		switch (localName) {
			case "proto":
				protoName = atts.getValue("name");
				if (protoName.equals("http")) {
					responseIn = null;
					sb.setLength(0);
				}
				break;
			case "field":
				switch (atts.getValue("name")) {
					case "num":
						if (protoName.equals("geninfo")) {
							frameNumber = Integer.parseInt(atts.getValue("show"));
						}
						break;
					case "timestamp":
						timestamp = atts.getValue("show");
						break;
					case "http.response_in":
						responseIn = Integer.valueOf(atts.getValue("show"));
						break;
					case "":
						if (!protoName.equals("http")) break;
					case "http.request.line":
					case "http.response.line":
					case "http.file_data":
						sb.append(atts.getValue("value"));
						break;
					case "http.request.method":
						method = atts.getValue("show");
						break;
					case "http.request.full_uri":
						try {
							url = new URL(atts.getValue("show"));
						} catch (Exception e) {
							e.printStackTrace(new PrintStream(callbacks.getStderr()));
						}
						break;
					case "http.response.code":
						status = Short.parseShort(atts.getValue("show"));
						break;
				}
				break;
		}
	}

	@Override
	public void endElement(String uri, String localName, String qName) {
		if (localName.equals("proto") && protoName.equals("http")) {
			byte[] decoded = decodeHex(sb);
			if (responseIn == null) {
				Request r = requests.get(frameNumber);
				if (r != null) model.addElement(r.complete(decoded, status));
			} else {
				requests.put(responseIn, new Request(decoded, method, url, timestamp, frameNumber));
			}
		}
	}

	private void fillModelFromPDML(final File pdmlFile)
			throws IOException, ParserConfigurationException, SAXException {

		SAXParserFactory spf = SAXParserFactory.newInstance();
		spf.setNamespaceAware(true);
		SAXParser saxParser = spf.newSAXParser();
		saxParser.parse(pdmlFile, this);
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
