package org.umbra.android

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.umbra.android.ui.PButton
import org.umbra.android.ui.PField
import org.umbra.android.ui.PScreen
import org.umbra.android.ui.PStyle
import org.umbra.android.ui.PText
import org.umbra.android.ui.Penumbra

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

    PScreen(title = if (creating) "Create your identity" else "Unlock") {
        val acc = Penumbra.colors.acc
        val bg = Penumbra.colors.bg
        Canvas(Modifier.padding(top = 8.dp, bottom = 16.dp).size(56.dp)) {
            val r = size.minDimension / 2
            drawCircle(acc, radius = r, center = center)
            drawCircle(bg, radius = r * .82f, center = Offset(center.x + r * .42f, center.y - r * .12f))
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            PField(passphrase, { passphrase = it }, "Passphrase", password = true, enabled = !busy)
            if (creating) {
                PField(confirm, { confirm = it }, "Confirm passphrase", password = true, enabled = !busy)
                if (tooShort && passphrase.isNotEmpty()) {
                    PText("At least $MIN_NEW_PASSPHRASE_LEN characters.", style = PStyle.Caption, color = Penumbra.colors.err)
                } else if (mismatch && confirm.isNotEmpty()) {
                    PText("Passphrases do not match.", style = PStyle.Caption, color = Penumbra.colors.err)
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        PButton(if (busy) "Working…" else if (creating) "Create" else "Unlock", enabled = canSubmit) {
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
        }
        error?.let { PText(it, Modifier.padding(top = 8.dp), style = PStyle.Caption, color = Penumbra.colors.err) }
    }
}
