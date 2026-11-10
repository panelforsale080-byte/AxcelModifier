package com.axcel.modifier;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;

public class MainActivity extends Activity {
    private final ArrayList<String> rows = new ArrayList<>();
    private ArrayAdapter<String> adapter;
    private TextView status;
    private EditText query;
    private TextView result;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#1C1C1E"));
        int pad = dp(12);
        root.setPadding(pad, pad, pad, pad);

        TextView title = label("AxcelModifier", 20, true);
        root.addView(title);

        Button refresh = button("Refresh processes");
        refresh.setOnClickListener(v -> loadProcesses());
        root.addView(refresh);

        ListView list = new ListView(this);
        adapter = new ArrayAdapter<>(this, R.layout.row, rows);
        list.setAdapter(adapter);
        list.setOnItemClickListener((parent, view, position, id) -> onProcess(rows.get(position)));
        root.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(220)));

        status = label("Select a process. IL2CPP domain is read automatically.", 14, false);
        root.addView(status);

        query = new EditText(this);
        query.setHint("Class name or il2cpp offset 0x208020");
        query.setTextColor(Color.parseColor("#F2F2F7"));
        query.setHintTextColor(Color.parseColor("#8E8E93"));
        query.setInputType(InputType.TYPE_CLASS_TEXT);
        root.addView(query);

        Button search = button("Search");
        search.setOnClickListener(v -> runSearch());
        root.addView(search);

        result = label("", 13, false);
        result.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(result);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
        loadProcesses();
    }

    private void loadProcesses() {
        rows.clear();
        String text = Native.listProcesses();
        if (text != null) {
            for (String line : text.split("\n")) {
                if (!line.isEmpty()) rows.add(line);
            }
        }
        if (adapter != null) adapter.notifyDataSetChanged();
    }

    private void onProcess(String line) {
        int space = line.indexOf(' ');
        if (space <= 0) return;
        int pid;
        try {
            pid = Integer.parseInt(line.substring(0, space));
        } catch (NumberFormatException e) {
            status.setText("bad pid");
            return;
        }
        status.setText("Reading IL2CPP domain…");
        new Thread(() -> {
            String msg = Native.attach(pid);
            runOnUiThread(() -> status.setText(msg == null ? "attach failed" : msg));
        }).start();
    }

    private void runSearch() {
        String q = query.getText() == null ? "" : query.getText().toString();
        result.setText("Searching…");
        new Thread(() -> {
            String msg = Native.search(q);
            runOnUiThread(() -> result.setText(msg == null ? "search failed" : msg));
        }).start();
    }

    private TextView label(String text, int sp, boolean bold) {
        TextView v = new TextView(this);
        v.setText(text);
        v.setTextSize(sp);
        v.setTextColor(Color.parseColor("#F2F2F7"));
        if (bold) v.setGravity(Gravity.START);
        v.setPadding(0, dp(4), 0, dp(4));
        return v;
    }

    private Button button(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(Color.parseColor("#F2F2F7"));
        b.setBackgroundColor(Color.parseColor("#3A3A3C"));
        return b;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
