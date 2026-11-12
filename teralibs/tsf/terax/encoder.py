from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.services.printf import error, info, warning


class TeraxEncoder:
    """Encoding pipeline utilities: explicit pass-through and auto-selection."""

    @staticmethod
    def rank_label(rank):
        """Return the human-readable label for an encoder rank object."""
        label_fn = getattr(rank, "label", None)
        return label_fn() if callable(label_fn) else str(rank)

    @staticmethod
    def encode_explicit(payload, encoder_name, arch, bad_bytes, iterations):
        """Run a named encoder for the given number of passes over payload."""
        name_norm = encoder_name.replace(".", "/").removeprefix("modules.encoder.")
        noun = "iteration" if iterations == 1 else "iterations"
        info(f"using '{name_norm}' to encode the payload with ({iterations} {noun})")

        current = payload
        pad = len(str(iterations))

        for n in range(1, iterations + 1):
            result = EncoderFactory.encode_payload(
                raw_bad_bytes=(current, bad_bytes),
                encoder_name=name_norm,
                arch=arch,
            )
            if not result.success:
                error(f"encoding failed at pass {n}: {result.error}")
                return None

            current = result.encoded_bytes
            key_tag = f"key: 0x{result.key_used:02x}" if isinstance(result.key_used, int) else ""
            info(f"pass {n:>{pad}}/{iterations} (size: {len(current)} bytes, {key_tag})")

        return current

    @staticmethod
    def encode_auto(payload, arch, bad_bytes, verbose):
        """Auto-select and apply the highest-ranked compatible encoder."""
        candidates = EncoderFactory.suggest(bad_bytes, arch)
        if not candidates:
            warning("no compatible encoder found — delivering payload unencoded. Use -e to specify one manually.")
            return payload

        chosen = candidates[0]
        info(f"auto-selecting encoder: {chosen.NAME}  [{TeraxEncoder.rank_label(chosen.RANK)}]")

        result = EncoderFactory.encode_payload(
            raw_bad_bytes=(payload, bad_bytes),
            encoder_name=chosen.NAME,
            arch=arch,
        )
        if not result.success:
            warning(f"auto-encoding failed: {result.error} — delivering payload unencoded.")
            return payload

        if verbose:
            key_tag = f"key: 0x{result.key_used:02x}" if isinstance(result.key_used, int) else ""
            info(f"encoded: {len(result.encoded_bytes):,} bytes, {key_tag}")

        return result.encoded_bytes
