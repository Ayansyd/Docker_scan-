def format_trivy_output(raw_output):
    """
    Format Trivy's raw output for better readability.
    """
    formatted_output = []
    for line in raw_output.splitlines():
        if "CRITICAL" in line:
            formatted_output.append(f"🚨 CRITICAL: {line}")
        elif "HIGH" in line:
            formatted_output.append(f"⚠️ HIGH: {line}")
        elif "MEDIUM" in line:
            formatted_output.append(f"⚡ MEDIUM: {line}")
        elif "LOW" in line:
            formatted_output.append(f"ℹ️ LOW: {line}")
        elif "CVE-" in line:
            formatted_output.append(f"🔍 {line}")
        elif "Total:" in line:
            formatted_output.append(f"📊 {line}")
        else:
            formatted_output.append(line)
    return "\n".join(formatted_output)
