package bcpi;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

import com.google.common.collect.ImmutableSet;

import java.util.Set;
import java.util.Objects;

/**
 * A set of fields accessed in a block.
 */
public class AccessPattern {
	private final Set<DataTypeComponent> fields;

	public AccessPattern(Set<DataTypeComponent> fields) {
		this.fields = ImmutableSet.copyOf(fields);
	}

	public Set<DataTypeComponent> getFields() {
		return this.fields;
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder();

		DataType struct = null;
		for (DataTypeComponent field : this.fields) {
			if (struct == null) {
				struct = field.getParent();
				result.append(struct.getName())
					.append("::{");
			} else {
				result.append(", ");
			}
			result.append(field.getFieldName());
		}

		return result
			.append("}")
			.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof AccessPattern)) {
			return false;
		}

		AccessPattern other = (AccessPattern) obj;
		return this.fields.equals(other.fields);
	}

	@Override
	public int hashCode() {
		return Objects.hash(fields);
	}
}
