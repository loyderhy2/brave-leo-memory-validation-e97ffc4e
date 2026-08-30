const d = db.getSiblingDB('trrtest');
const names = [
  'normal',
  '../TRR_PATH_PARENT',
  '../../TRR_PATH_GRANDPARENT',
  'nested/TRR_PATH_CHILD',
  '<img src="http://127.0.0.1:8765/TRR_HTML_IMG_COLLECTION">',
  '<svg onload="fetch(\'http://127.0.0.1:8765/TRR_HTML_ONLOAD_COLLECTION\')"></svg>',
  '\"><img src=x onerror="fetch(\'http://127.0.0.1:8765/TRR_HTML_ATTR_BREAKOUT_COLLECTION\')">',
  '</script><script>fetch(\'http://127.0.0.1:8765/TRR_HTML_SCRIPT_BREAKOUT_COLLECTION\')</script>',
  'javascript:fetch(\'http://127.0.0.1:8765/TRR_JS_SCHEME_COLLECTION\')',
  'file:///tmp/TRR_FILE_SCHEME_COLLECTION',
  'data:text/html,<script>fetch(\'http://127.0.0.1:8765/TRR_DATA_SCHEME_COLLECTION\')</script>',
  '=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_EQ_COLLECTION","open")',
  '+HYPERLINK("http://127.0.0.1:8765/TRR_CSV_PLUS_COLLECTION","open")',
  '-1+1',
  '@SUM(1,1)',
  '\t=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_TAB_COLLECTION","open")',
  '\r=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_CR_COLLECTION","open")'
];
for (const name of names) {
  try {
    d.createCollection(name);
    d.getCollection(name).insertOne({
      normal: 1,
      '<img src="http://127.0.0.1:8765/TRR_HTML_IMG_FIELD">': 'x',
      '<svg onload="fetch(\'http://127.0.0.1:8765/TRR_HTML_ONLOAD_FIELD\')"></svg>': 'x',
      '\"><img src=x onerror="fetch(\'http://127.0.0.1:8765/TRR_HTML_ATTR_BREAKOUT_FIELD\')">': 'x',
      '</script><script>fetch(\'http://127.0.0.1:8765/TRR_HTML_SCRIPT_BREAKOUT_FIELD\')</script>': 'x',
      'javascript:fetch(\'http://127.0.0.1:8765/TRR_JS_SCHEME_FIELD\')': 'x',
      '=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_EQ_FIELD","open")': 'x',
      '+HYPERLINK("http://127.0.0.1:8765/TRR_CSV_PLUS_FIELD","open")': 'x',
      '-2+2': 'x',
      '@SUM(2,2)': 'x',
      '\t=HYPERLINK("http://127.0.0.1:8765/TRR_CSV_TAB_FIELD","open")': 'x'
    });
  } catch (e) {
    print('SEED_ERROR:' + name + ':' + e);
  }
}
printjson(d.getCollectionNames());
