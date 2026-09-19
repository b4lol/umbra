package org.umbra.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun HomeScreen(peersVersion: Int, onPair: () -> Unit, onLock: () -> Unit) {
    var peers by remember { mutableStateOf<List<String>?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(peersVersion) {
        ffi { AppCore.controller.listPeers() }
            .onSuccess { peers = it; error = null }
            .onFailure { error = it.userMessage("Could not list peers") }
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Peers", style = MaterialTheme.typography.headlineSmall)
            OutlinedButton(onClick = onLock) { Text("Lock") }
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        val list = peers
        if (list == null) {
            Text("Loading…", modifier = Modifier.padding(top = 16.dp))
        } else if (list.isEmpty()) {
            Text("No peers paired yet.", modifier = Modifier.padding(top = 16.dp))
        } else {
            LazyColumn(modifier = Modifier.weight(1f).padding(top = 16.dp)) {
                items(list) { name -> Text(name, modifier = Modifier.padding(vertical = 8.dp)) }
            }
        }
        Button(onClick = onPair, modifier = Modifier.padding(top = 16.dp)) { Text("Pair a peer") }
    }
}
