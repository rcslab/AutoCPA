package bcpi;

import java.util.Objects;

/**
 * Metadata about a struct field reference.
 */
public class FieldReference {
	private final Field field;
	private final boolean arrayAccess;

	FieldReference(Field field, boolean arrayAccess) {
		this.field = field;
		this.arrayAccess = arrayAccess;
	}

	/** The field being accessed. */
	public Field getField() {
		return this.field;
	}

	/** Whether this field was accessed as part of an array. */
	public boolean isArrayAccess() {
		return this.arrayAccess;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof FieldReference)) {
			return false;
		}

		FieldReference other = (FieldReference) obj;
		return this.field.equals(other.field)
			&& this.arrayAccess == other.arrayAccess;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.field, this.arrayAccess);
	}

	@Override
	public String toString() {
		String parent = this.field.getParent().getName();
		String array = this.arrayAccess ? "[]" : "";
		String name = this.field.getFieldName();
		return String.format("%s%s::%s", parent, array, name);
	}
}
