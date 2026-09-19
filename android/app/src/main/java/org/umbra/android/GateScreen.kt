package org.umbra.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** Minimum length when CREATING a keystore: it is attackable offline, so a floor is worth the friction. */
private const val MIN_NEW_PASSPHRASE_LEN = 12

/**
 * Creates a keystore on first run, otherwise unlocks the existing one.
 *
 * Honest scope: the passphrase is a JVM String (and Compose text state) which cannot be
 * zeroized — the same accepted residual as the Linux GUI's PasswordEntry.
 */
@Composable
fun GateScreen(onUnlocked: () -> Unit) {
    val context = LocalContext.current
    val keystore = remember { AppCore.keystoreFile(context) }
    val creating = remember { !keystore.exists() }
    var passphrase by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val tooShort = creating && passphrase.length < MIN_NEW_PASSPHRASE_LEN
    val mismatch = creating && passphrase != confirm
    val canSubmit = !busy && passphrase.isNotEmpty() && !tooShort && !mismatch

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = if (creating) "Create your identity" else "Unlock",
            style = MaterialTheme.typography.headlineSmall,
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = { Text("Passphrase") },
            singleLine = true,
            enabled = !busy,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        )
        if (creating) {
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text("Confirm passphrase") },
                singleLine = true,
                enabled = !busy,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
            if (tooShort && passphrase.isNotEmpty()) {
                Text("At least $MIN_NEW_PASSPHRASE_LEN characters.", color = MaterialTheme.colorScheme.error)
            } else if (mismatch && confirm.isNotEmpty()) {
                Text("Passphrases do not match.", color = MaterialTheme.colorScheme.error)
            }
        }
        Button(
            enabled = canSubmit,
            modifier = Modifier.padding(top = 16.dp),
            onClick = {
                busy = true
                error = null
                val pass = passphrase
                scope.launch {
                    val result = ffi {
                        if (creating) AppCore.controller.createIdentity(keystore.absolutePath, pass)
                        else AppCore.controller.unlockIdentity(keystore.absolutePath, pass)
                    }
                    busy = false
                    passphrase = ""
                    confirm = ""
                    result
                        .onSuccess { onUnlocked() }
                        .onFailure { error = it.userMessage("Operation failed") }
                }
            },
        ) { Text(if (busy) "Working…" else if (creating) "Create" else "Unlock") }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp)) }
    }
}
