package bcpi;

import ghidra.program.model.data.DataType;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import java.util.Set;
import java.util.Objects;

/**
 * A set of fields accessed in a block.
 */
public class AccessPattern {
	private final Set<Field> read;
	private final Set<Field> written;

	public AccessPattern(Set<Field> read, Set<Field> written) {
		this.read = ImmutableSet.copyOf(read);
		this.written = ImmutableSet.copyOf(written);
	}

	public Set<Field> getFields() {
		return Sets.union(this.read, this.written);
	}

	public Set<Field> getReadFields() {
		return this.read;
	}

	public Set<Field> getWrittenFields() {
		return this.written;
	}

	@Override
	public String toString() {
		StringBuilder result = new StringBuilder();

		DataType struct = null;
		for (Field field : this.getFields()) {
			if (struct == null) {
				struct = field.getParent();
				result.append(struct.getName())
					.append("::{");
			} else {
				result.append(", ");
			}
			result.append(field.getFieldName())
				.append("(");
			if (this.read.contains(field)) {
				result.append("R");
			}
			if (this.written.contains(field)) {
				result.append("W");
			}
			result.append(")");
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
		return this.read.equals(other.read)
			&& this.written.equals(other.written);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.read, this.written);
	}
}
