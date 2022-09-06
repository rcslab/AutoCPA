package bcpi;

import ghidra.program.model.data.Structure;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * ABI constraints on struct layouts.
 */
public class StructAbiConstraints {
	private final Structure struct;
	private final List<Field> fields;
	private final Map<String, Integer> indices;
	private final int[] fixed;
	private final int[] groups;
	private final SetMultimap<Integer, Integer> groupOrdering;

	public StructAbiConstraints(Structure struct) {
		this.struct = struct;
		this.fields = Field.allFields(struct);

		int nFields = this.fields.size();
		this.indices = IntStream.range(0, nFields)
			.boxed()
			.collect(Collectors.toMap(i -> this.fields.get(i).getFieldName(), i -> i));

		this.fixed = new int[nFields];
		for (int i = 0; i < nFields; ++i) {
			if (this.fields.get(i).isSuperClass()) {
				this.fixed[i] = i;
			} else {
				this.fixed[i] = -1;
			}
		}

		this.groups = new int[nFields];
		Arrays.fill(this.groups, -1);

		this.groupOrdering = HashMultimap.create();
	}

	private int getIndex(String field) {
		int index = this.indices.getOrDefault(field, -1);
		if (index < 0) {
			throw new IllegalArgumentException("No such field " + field);
		}
		return index;
	}

	private int getIndex(Field field) {
		return getIndex(field.getFieldName());
	}

	private void setGroup(int index, int group) {
		int prev = this.groups[index];
		if (prev != -1) {
			Field field = this.fields.get(index);
			throw new IllegalArgumentException(String.format("Conflicting groups %d and %d for %s", prev, group, field));
		}
		this.groups[index] = group;
	}

	/** Set the group constraint for a field. */
	public void setGroup(String field, int group) {
		setGroup(getIndex(field), group);
	}

	/** Set the group constraint for a range of fields. */
	public void setRangeGroup(String from, String to, int group) {
		int start = getIndex(from);
		int end = getIndex(to);
		Objects.checkFromToIndex(start, end, this.groups.length);
		for (int i = start; i <= end; ++i) {
			setGroup(i, group);
		}
	}

	/** Constrain the relative orders of two groups. */
	public void orderGroups(int before, int after) {
		this.groupOrdering.put(before, after);
	}

	/** Set a fixed position for a field. */
	public void setFixed(String field, int index) {
		int i = getIndex(field);
		this.fixed[i] = index;
	}

	/**
	 * @return Whether the given field has its position fixed.
	 */
	public boolean isFixed(Field field) {
		return this.fixed[getIndex(field)] >= 0;
	}

	/**
	 * @return Whether this field order satisfies the constraints.
	 */
	public boolean check(List<Field> fields, int i) {
		if (!checkFixed(fields)) {
			return false;
		}

		if (!checkGroups(fields, i)) {
			return false;
		}

		return true;
	}

	/** Check fixed field constraints. */
	private boolean checkFixed(List<Field> fields) {
		for (int i = 0; i < fields.size(); ++i) {
			Field field = fields.get(i);
			int expected = this.fixed[getIndex(field)];
			if (expected >= 0 && i != expected) {
				return false;
			}
		}

		return true;
	}

	/** Check group constraints. */
	private boolean checkGroups(List<Field> fields, int i) {
		int group = getGroup(fields.get(i));
		if (group == -1) {
			// No group constraints for this field
			return true;
		}

		int start = -1, end = -1;
		for (int j = 0; j < fields.size(); ++j) {
			int other = getGroup(fields.get(j));
			if (other == group) {
				if (start < 0) {
					start = j;
				}
				end = j;
			} else if (j < i && !checkGroupOrdering(other, group)) {
				return false;
			} else if (j > i && !checkGroupOrdering(group, other)) {
				return false;
			}
		}

		return i >= start && i <= end;
	}

	private int getGroup(Field field) {
		return this.groups[getIndex(field)];
	}

	/** Check the relative order of two groups. */
	private boolean checkGroupOrdering(int before, int after) {
		return !this.groupOrdering.get(after).contains(before);
	}
}
